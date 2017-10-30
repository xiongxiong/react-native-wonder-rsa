using ReactNative.Bridge;
using System;
using System.Collections.Generic;
using Windows.ApplicationModel.Core;
using Windows.UI.Core;

namespace Wonder.Rsa.RNWonderRsa
{
    /// <summary>
    /// A module that allows JS to share data.
    /// </summary>
    class RNWonderRsaModule : NativeModuleBase
    {
        /// <summary>
        /// Instantiates the <see cref="RNWonderRsaModule"/>.
        /// </summary>
        internal RNWonderRsaModule()
        {

        }

        /// <summary>
        /// The name of the native module.
        /// </summary>
        public override string Name
        {
            get
            {
                return "RNWonderRsa";
            }
        }
    }
}
