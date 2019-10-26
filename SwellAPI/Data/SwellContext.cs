using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SwellAPI.Data
{
    public class SwellContext:IdentityDbContext
    {
       
        public SwellContext(DbContextOptions<SwellContext> options) : base(options)
        {
            
        }
    }
}
