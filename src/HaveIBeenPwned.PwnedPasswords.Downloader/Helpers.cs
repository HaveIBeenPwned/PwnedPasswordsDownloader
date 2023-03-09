// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Concurrent;
using System.IO.Pipelines;
using Microsoft.Win32.SafeHandles;

namespace HaveIBeenPwned.PwnedPasswords
{
    internal static class Helpers
    {
        private static readonly ConcurrentStack<Pipe> s_pipes = new();

        private static Pipe GetPipe()
        {
            if (!s_pipes.TryPop(out Pipe? result))
            {
                return new Pipe();
            }

            result.Reset();
            return result;
        }

        private static async Task CompleteWriter(Task previousTask, object? state)
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
                await copyTask.ConfigureAwait(false);
                await pipe.Reader.CompleteAsync().ConfigureAwait(false);
                s_pipes.Push(pipe);
            }
        }
    }
}
