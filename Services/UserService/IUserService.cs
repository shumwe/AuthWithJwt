using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthWithJwt.Services.UserService
{
    public interface IUserService
    {

        public string GetMyName();
        public string GetMyRole();
        
    }
}