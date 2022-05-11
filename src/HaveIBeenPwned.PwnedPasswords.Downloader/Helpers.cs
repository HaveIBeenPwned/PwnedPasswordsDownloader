// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;

namespace HaveIBeenPwned.PwnedPasswords
{
    internal static class Helpers
    {
        private static readonly Encoding s_encoding = Encoding.UTF8;
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

        internal static bool TryReadLine(ref ReadOnlySequence<byte> buffer, bool isComplete, out string? line)
        {
            while (buffer.Length > 0)
            {
                SequencePosition? position = buffer.PositionOf((byte)'\n');
                if (position.HasValue)
                {
                    ReadOnlySequence<byte> slice = buffer.Slice(buffer.Start, position.Value);
                    int sliceLength = (int)slice.Length;
                    buffer = buffer.Slice(sliceLength + 1);
                    line = s_encoding.GetString(slice.Slice(0, sliceLength)).Trim();
                    return true;
                }
                else if (isComplete)
                {
                    // The pipe is complete but we don't have a newline character, this input probably ends without a newline char.
                    line = s_encoding.GetString(buffer).Trim();
                    buffer = buffer.Slice(buffer.End, 0);
                    return true;
                }
                else
                {
                    break;
                }
            }

            line = "";
            return false;
        }

        internal static async IAsyncEnumerable<string> ReadLinesAsync<T>(this T pipeReader) where T : PipeReader
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
                while (TryReadLine(ref buffer, result.IsCompleted, out string? line))
                {
                    if (line != null)
                    {
                        yield return line;
                    }
                }

                pipeReader.AdvanceTo(buffer.Start, buffer.End);
            }

            await pipeReader.CompleteAsync().ConfigureAwait(false);
        }

        internal static async IAsyncEnumerable<string> ParseLinesAsync<T>(this T stream) where T : Stream
        {
            Pipe inputPipe = GetPipe();
            Task copyTask = stream.CopyToAsync(inputPipe.Writer).ContinueWith(CompleteWriter, inputPipe.Writer).Unwrap();

            await foreach (string line in inputPipe.Reader.ReadLinesAsync())
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
    }
}
