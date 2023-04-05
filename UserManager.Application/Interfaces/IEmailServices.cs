using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UserManager.Application.Models;

namespace UserManager.Application.Interfaces
{
    public interface IEmailServices
    {
        void SendEmail(Message message);
    }
}
