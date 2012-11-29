using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace HardwareTokenValidationService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the interface name "IService1" in both code and config file together.
    [ServiceContract]
    public interface IValidationService
    {

        [OperationContract]
        bool ValidateToken(byte[] token, byte[] nonce, byte[] certificate, byte[] signature);

        // TODO: Add your service operations here

    }
}
