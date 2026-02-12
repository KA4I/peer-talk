using System;
using System.Collections.Generic;

namespace PeerTalk.Routing
{
    /// <summary>
    /// Selects the best value from a selection of values using a selector function
    /// </summary>
    public class Selector
    {
        private readonly Dictionary<string, Func<string, byte[][], int>> _selectors;

        /// <summary>
        /// Creates a new default selector and registers the public key selector
        /// </summary>
        public Selector()
            : this(new Dictionary<string, Func<string, byte[][], int>>())
        {
            this._selectors.Add("pk", PublicKeySelector);
        }

        /// <summary>
        /// Creates a new selector using the specified selector functions
        /// </summary>
        /// <param name="selectors"></param>
        public Selector(Dictionary<string, Func<string, byte[][], int>> selectors)
        {
            _selectors = selectors;
        }

        /// <summary>
        /// Selects the best record 
        /// </summary>
        /// <param name="key">The key that the records share</param>
        /// <param name="records">The possible values of the records</param>
        /// <returns></returns>
        public int BestRecord(string key, params byte[][] records)
        {
            if (records.Length == 0)
                return 0;

            var parts = key.Split('/');
            if (parts.Length < 3)
                return 0;

            Func<string, byte[][], int> sel;
            if (!_selectors.TryGetValue(parts[1], out sel))
                return 0;

            return sel(key, records);
        }

        /// <summary>
        /// Provides a Public Key selector function
        /// </summary>
        /// <param name="key">The key that the records share</param>
        /// <param name="records">The possible values of the records</param>
        /// <returns>0 - all public key records are created equally</returns>
        public static int PublicKeySelector(string key, params byte[][] records)
        {
            return 0;
        }
    }
}