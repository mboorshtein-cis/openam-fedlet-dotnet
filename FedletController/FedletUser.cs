using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gov.dhs.uscis.icam.fedlet
{
    public class FedletUser
    {
        public string UserName { get; set; }
        public Dictionary<string, string> Attributes { get; private set; }

        public FedletUser()
        {
            this.Attributes = new Dictionary<string, string>();
        }
    }
}
