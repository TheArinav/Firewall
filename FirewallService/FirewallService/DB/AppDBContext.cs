﻿using FirewallService.DB.Entities;
using Microsoft.EntityFrameworkCore;

namespace FirewallService.DB;
public class AppDBContext : DbContext
{
    public DbSet<FirewallRule> FirewallRules { get; set; }
    public DbSet<Connection> Connections { get; set; }
    public DbSet<ConnectionClass> ConnectionClasses { get; set; }
    public DbSet<Enforcer> Enforcers { get; set; }
    public DbSet<Packet> Packets { get; set; }
    public DbSet<PayloadLengthEnforcer> PayloadLengthEnforcers { get; set; }
    public DbSet<Protocol> Protocols { get; set; }
    public DbSet<Record> Records { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlite("Data Source=Firewall.db");
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configure the primary keys
        modelBuilder.Entity<ConnectionClass>().HasKey(c => c.ClassID);
        modelBuilder.Entity<Connection>().HasKey(c => c.ConnectionID);
        modelBuilder.Entity<Packet>().HasKey(p => p.PacketID);
        modelBuilder.Entity<Enforcer>().HasKey(e => e.EnforcerID);
        modelBuilder.Entity<PayloadLengthEnforcer>().HasKey(p => p.EnforcerID);
        modelBuilder.Entity<Protocol>().HasKey(p => p.ProtocolID);
        modelBuilder.Entity<FirewallRule>().HasKey(f => f.RuleID);
        modelBuilder.Entity<Record>().HasKey(r => r.RecordID);

        // Configure relationships
        modelBuilder.Entity<Connection>()
            .HasOne(c => c.ConnectionClass)
            .WithMany(cc => cc.Connections)
            .HasForeignKey(c => c.ConnectionClassID);

        modelBuilder.Entity<Packet>()
            .HasOne(p => p.SourceConnection)
            .WithMany(c => c.SourcePackets)
            .HasForeignKey(p => p.Source)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Packet>()
            .HasOne(p => p.DestinationConnection)
            .WithMany(c => c.DestinationPackets)
            .HasForeignKey(p => p.Destination)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<PayloadLengthEnforcer>()
            .HasOne(p => p.Enforcer)
            .WithMany(e => e.PayloadLengthEnforcers)
            .HasForeignKey(p => p.EnforcerID);

        modelBuilder.Entity<Protocol>()
            .HasOne(p => p.Enforcer)
            .WithMany(e => e.Protocols)
            .HasForeignKey(p => p.EnforcerID);

        modelBuilder.Entity<FirewallRule>()
            .HasOne(f => f.ConnectionClass)
            .WithMany()
            .HasForeignKey(f => f.ConnectionClassID);
        
        modelBuilder.Entity<FirewallRule>()
            .HasOne(f => f.Protocol)
            .WithMany(p => p.FirewallRules)
            .HasForeignKey(f => f.ProtocolID);

        modelBuilder.Entity<Record>()
            .HasOne(r => r.Packet)
            .WithMany()
            .HasForeignKey(r => r.PacketID);

        modelBuilder.Entity<Record>()
            .HasOne(r => r.FirewallRule)
            .WithMany(f => f.Records)
            .HasForeignKey(r => r.RuleID);
    }
}