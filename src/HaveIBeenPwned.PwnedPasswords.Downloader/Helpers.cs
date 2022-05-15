// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;

using Microsoft.Win32.SafeHandles;

namespace HaveIBeenPwned.PwnedPasswords
{
    internal static class Helpers
    {
        private static readonly ConcurrentStack<Pipe> s_pipes = new();

        private static Pipe GetPipe()
        {
            if (s_pipes.TryPop(out Pipe? result))
            {
                result.Reset();
                return result;
            }

            return new Pipe();
        }

        internal static bool TryReadLine(ref ReadOnlySequence<byte> buffer, bool isComplete, out ReadOnlySequence<byte> line)
        {
            while (buffer.Length > 0)
            {
                SequencePosition? position = buffer.PositionOf((byte)'\n');
                if (position.HasValue)
                {
                    line = buffer.Slice(buffer.Start, position.Value);
                    buffer = buffer.Slice(line.Length + 1);
                    return true;
                }
                else if (isComplete)
                {
                    // The pipe is complete but we don't have a newline character, this input probably ends without a newline char.
                    line = buffer;
                    buffer = buffer.Slice(buffer.End, 0);
                    return true;
                }
                else
                {
                    break;
                }
            }

            line = default;
            return false;
        }

        internal static ReadOnlyMemory<char> GetChars(this ReadOnlySequence<byte> sequence, Encoding encoding)
        {
            if (sequence.IsSingleSegment)
            {
                return sequence.FirstSpan.GetChars(Encoding.UTF8);
            }
            else
            {
                byte[]? tempArray = null;
                try
                {
                    int requiredLength = (int)sequence.Length;
                    Span<byte> tempSpan = requiredLength <= 512 ? stackalloc byte[512] : (tempArray = ArrayPool<byte>.Shared.Rent(requiredLength));
                    sequence.CopyTo(tempSpan);
                    return ((ReadOnlySpan<byte>)tempSpan).Slice(0, requiredLength).GetChars(Encoding.UTF8);
                }
                finally
                {
                    if (tempArray != null)
                    {
                        ArrayPool<byte>.Shared.Return(tempArray);
                    }
                }
            }
        }

        private static ReadOnlyMemory<char> GetChars(this ReadOnlySpan<byte> byteSpan, Encoding encoding)
        {
            int charCount = encoding.GetCharCount(byteSpan);
            char[] lineArray = ArrayPool<char>.Shared.Rent(charCount);
            Span<char> lineSpan = lineArray;
            lineSpan = lineSpan.Slice(0, encoding.GetChars(byteSpan, lineSpan)).Trim();
            return new Memory<char>(lineArray, 0, lineSpan.Length);
        }

        internal static async IAsyncEnumerable<ReadOnlyMemory<char>> ReadLinesAsync<T>(this T pipeReader) where T : PipeReader
        {
            while (true)
            {
                if (!pipeReader.TryRead(out ReadResult result))
                {
                    await pipeReader.ReadAsync().ConfigureAwait(false);
                }

                if (result.Buffer.IsEmpty && result.IsCompleted)
                {
                    break;
                }

                ReadOnlySequence<byte> buffer = result.Buffer;
                while (TryReadLine(ref buffer, result.IsCompleted, out ReadOnlySequence<byte> line))
                {
                    yield return line.GetChars(Encoding.UTF8);
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        internal static async IAsyncEnumerable<ReadOnlyMemory<char>> ParseLinesAsync<T>(this T stream) where T : Stream
        {
            Pipe inputPipe = GetPipe();
            Task copyTask = stream.CopyToAsync(inputPipe.Writer).ContinueWith(CompleteWriter, inputPipe.Writer).Unwrap();

            await foreach (ReadOnlyMemory<char> line in inputPipe.Reader.ReadLinesAsync())
            {
                yield return line;
            }

            await copyTask.ConfigureAwait(false);
            s_pipes.Push(inputPipe);
        }

        internal static async Task CompleteWriter(Task previousTask, object? state)
        {
            if (previousTask.IsCompleted && state is PipeWriter pipeWriter)
            {
                await pipeWriter.FlushAsync().ConfigureAwait(false);
                await pipeWriter.CompleteAsync().ConfigureAwait(false);
            }
        }

        internal static async Task CopyFrom<T>(this SafeFileHandle handle, T stream, int offset = 0) where T : Stream
        {
            var pipe = GetPipe();
            Task copyTask = stream.CopyToAsync(pipe.Writer).ContinueWith(CompleteWriter, pipe.Writer).Unwrap();

            try
            {
                while (true)
                {
                    if (!pipe.Reader.TryRead(out ReadResult result))
                    {
                        await pipe.Reader.ReadAsync().ConfigureAwait(false);
                    }

                    foreach (ReadOnlyMemory<byte> item in result.Buffer)
                    {
                        await RandomAccess.WriteAsync(handle, item, offset).ConfigureAwait(false);
                        offset += item.Length;
                    }

                    pipe.Reader.AdvanceTo(result.Buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
            }
            finally
            {
                await pipe.Reader.CompleteAsync().ConfigureAwait(false);
                s_pipes.Push(pipe);
            }
        }
    }
}
