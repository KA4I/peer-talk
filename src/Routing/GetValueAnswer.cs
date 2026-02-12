using Ipfs;

namespace PeerTalk.Routing
{
    class GetValueAnswer
    {
        public GetValueAnswer(DhtMessage message, Peer peer)
        {
            Message = message;
            Peer = peer;
        }

        public Peer Peer { get; }

        public DhtMessage Message { get; }
    }
}