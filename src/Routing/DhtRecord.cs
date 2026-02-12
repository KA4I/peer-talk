using System;

namespace PeerTalk.Routing
{
    public class DhtRecord
    {
        public DhtRecord(byte[] value)
        {
            this.Value = value;
            this.TimeReceived = DateTime.UtcNow;
        }

        public byte[] Value { get; }

        public DateTime TimeReceived { get; }
    }
}