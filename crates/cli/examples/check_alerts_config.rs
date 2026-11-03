//! Validate a peg-out alert configuration without starting a node or sending
//! mail: parse it, resolve `${NAME}` references against the env file, and
//! report what would happen. Secrets are never printed — only whether they
//! resolved and how long they are.
//!
//! Usage: check_alerts_config <config.toml>

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: check_alerts_config <config.toml>");
    let all = rustock_alerts::Config::load(&path)?.alerts;
    let cfg = &all.pegout;
    let health = &all.node_health;

    println!("configuration {path} is valid\n");
    println!("  enabled              {}", cfg.enabled);
    println!("  poll interval        {}s", cfg.poll_interval_secs);
    println!("  peg-out threshold    {} BTC", cfg.pegout_alert_btc);
    println!("  output threshold     {} BTC", cfg.output_alert_btc);
    println!("  in-transit threshold {} BTC", cfg.in_transit_alert_btc);
    println!("  confirmations        {}", cfg.confirmations);
    println!("  change scripts       {}", cfg.federation_change_scripts.len());

    println!("\n  node health          {}", if health.enabled { "enabled" } else { "disabled" });
    if health.enabled {
        println!("    gap                {} blocks", health.block_gap);
        println!("    sustained for      {}s", health.for_secs);
        println!("    cooldown           {}s", health.cooldown_secs);
    }
    let contract = &all.contract_value;
    println!(
        "\n  contract value       {}",
        if contract.enabled { "enabled" } else { "disabled" }
    );
    if contract.enabled {
        println!("    transfer threshold {} RBTC", contract.transfer_alert_btc);
        println!("    threshold in wei   {}", contract.transfer_alert_wei());
        println!("    replay filter      {} RBTC", contract.replay_filter_btc);
        println!("    re-executes blocks up to {} behind the head", contract.max_catchup_blocks);
        println!("    NOTE: a block is re-executed only when some account's balance moved");
        println!("          more than the replay filter. On mainnet that is a very small");
        println!("          fraction of blocks.");
    }

    println!("\n  email                {}", if all.email.enabled { "enabled" } else { "disabled (log only)" });
    if all.email.enabled {
        println!("  smtp                 {}:{} ({:?})", all.email.smtp_host, all.email.smtp_port, all.email.tls);
        println!("  from                 {}", all.email.from);
        println!("  to                   {}", all.email.to.join(", "));
        // Report resolution without disclosing the value.
        let shown = |o: &Option<String>| match o {
            Some(v) if v.is_empty() => "resolved but EMPTY".to_string(),
            Some(v) if v.contains("${") => "UNRESOLVED".to_string(),
            Some(v) => format!("resolved, {} chars", v.len()),
            None => "not set".to_string(),
        };
        println!("  username             {}", shown(&all.email.username));
        println!("  password             {}", shown(&all.email.password));
        #[cfg(feature = "smtp")]
        {
            rustock_alerts::SmtpSink::new(&all.email)?;
            println!("\n  SMTP transport builds. No mail was sent.");
        }
        #[cfg(not(feature = "smtp"))]
        println!(
            "\n  NOTE: this binary was built without the `smtp` feature, so the\n  \
             transport was not checked and the node would refuse to start the\n  \
             watcher with email enabled. Rebuild with --features smtp."
        );
    }
    Ok(())
}
