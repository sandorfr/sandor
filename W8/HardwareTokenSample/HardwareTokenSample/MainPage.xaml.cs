using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using Windows.System.Profile;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace HardwareTokenSample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        /// <summary>
        /// Invoked when this page is about to be displayed in a Frame.
        /// </summary>
        /// <param name="e">Event data that describes how this page was reached.  The Parameter
        /// property is typically used to configure the page.</param>
        protected async override void OnNavigatedTo(NavigationEventArgs e)
        {
            var nonce = CryptographicBuffer.GenerateRandom(32);
            var token = HardwareIdentification.GetPackageSpecificToken(nonce);
            HardwareTokenSample.HTVS.ValidationServiceClient client = new HTVS.ValidationServiceClient();
            var result = await client.ValidateTokenAsync(GetBytes(token.Id), GetBytes(nonce), GetBytes(token.Certificate), GetBytes(token.Signature));
            MessageDialog dg = new MessageDialog(result ? "Valid" : "Invalid");
            dg.Title = "Hardware token is ";
            await dg.ShowAsync();
        }

        public byte[] GetBytes(IBuffer buffer)
        {
            byte[] bytes;
            CryptographicBuffer.CopyToByteArray(buffer, out bytes);
            return bytes;
        }
    }
}
