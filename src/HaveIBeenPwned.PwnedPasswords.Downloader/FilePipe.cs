// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;
using System.Text;

using Microsoft.Win32.SafeHandles;

namespace HaveIBeenPwned.PwnedPasswords
{
    internal class FilePipe : IDisposable
    {
        private readonly SafeFileHandle _handle;
        private readonly Pipe _pipe;
        private readonly Task _readerTask;
        private long _offset = 0;
        private bool _disposedValue;

        internal FilePipe(SafeFileHandle handle)
        {
            _handle = handle;
            _pipe = new Pipe();
            _readerTask = StartWriter();
        }

        private async Task StartWriter()
        {
            try
            {
                while (true)
                {
                    if (!_pipe.Reader.TryRead(out ReadResult result))
                    {
                        await _pipe.Reader.ReadAsync().ConfigureAwait(false);
                    }

                    foreach (ReadOnlyMemory<byte> item in result.Buffer)
                    {
                        await RandomAccess.WriteAsync(_handle, item, _offset).ConfigureAwait(false);
                        _offset += item.Length;
                    }

                    _pipe.Reader.AdvanceTo(result.Buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
            }
            finally
            {
                await _pipe.Reader.CompleteAsync().ConfigureAwait(false);
            }
        }

        internal void Write(ReadOnlySpan<byte> span)
        {
            Span<byte> destination = _pipe.Writer.GetSpan(span.Length);
            span.CopyTo(destination);
            _pipe.Writer.Advance(span.Length);
        }

        internal void Write(ReadOnlyMemory<char> memory) => Write(memory.Span);
        
        internal void Write(ReadOnlySpan<char> span)
        {
            _pipe.Writer.Advance(Encoding.UTF8.GetBytes(span, _pipe.Writer.GetSpan(Encoding.UTF8.GetByteCount(span))));
        }

        internal async ValueTask FlushAsync()
        {
            await _pipe.Writer.FlushAsync().ConfigureAwait(false);
        }

        internal async Task CloseAsync()
        {
            _pipe.Writer.Complete();
            if (_pipe.Writer.UnflushedBytes > 0)
            {
                await _pipe.Writer.FlushAsync().ConfigureAwait(false);
            }

            await _readerTask.ConfigureAwait(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _handle.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
