using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using ScanBuddy.Models;

namespace ScanBuddy.Context
{
    //ApplicationDbContext is the bridge between the models and the SQL database
    public class ApplicationDbContext : DbContext 
    {
        //Creates a table in the SQL databse for ApplicationUser model
        public DbSet<ApplicationUser> Users { get; set; }


        //This constructor accepts DbContextOptions which are used to configure the database connection and other options via dependency injection

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { } 


        //This method is called by the framework to configure the database context and it is only called if the context is not already configured in program.cs.
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)//(Loads the connection string from appsettings.json and Tells EF to use SQL Server as the database)
        {
            if (!optionsBuilder.IsConfigured)
            {
                //Loads the configuration settings from appsettings.json
                var configuration = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory()) //set the base path to the project directory
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)//load the appsettings.json file, which contains the database connection string and other settings
                    .Build();

                //Retreive the connection string named "Default Connection" 
                var connectionString = configuration.GetConnectionString("DefaultConnection");

                //Use the connection string to configure the database context to use SQL Server
                optionsBuilder.UseSqlServer(connectionString);
            }
        }

        //This method is called by the framework to configure the model when the database is created
        protected override void OnModelCreating(ModelBuilder modelBuilder) //(This lets you define rules like:Which columns are unique,Relationships between tables,Table/column names if you want to customize them)
        {
            //Make the UserName property unique in the database to prevent duplication
            modelBuilder.Entity<ApplicationUser>()
                .HasIndex(u => u.FullName)
                .IsUnique();

            //Make the Email property unique in the database to prevent duplication
            modelBuilder.Entity<ApplicationUser>()
                .HasIndex(u => u.Email)
                .IsUnique();

            //call the base class logic
            base.OnModelCreating(modelBuilder);
        }
    }
}