import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'eqx_multichain_vault.dart';

class EqxMultiChainSheet extends StatefulWidget {
  const EqxMultiChainSheet({super.key});

  @override
  State<EqxMultiChainSheet> createState() => _EqxMultiChainSheetState();
}

class _EqxMultiChainSheetState extends State<EqxMultiChainSheet> {
  bool _loading = true;
  List<ChainBalance> _balances = [];
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadVault();
  }

  Future<void> _loadVault() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      String? seed = await EqxMultiChainVault.loadSeedSecurely();
      if (seed == null || !EqxMultiChainVault.isValidMnemonic(seed)) {
        seed = EqxMultiChainVault.generateNewMnemonic();
        await EqxMultiChainVault.saveSeedSecurely(seed);
      }
      final addrs = await EqxMultiChainVault.deriveAddresses(seed);
      final list = await EqxMultiChainVault.fetchAllBalances(addrs);
      if (!mounted) return;
      setState(() {
        _balances = list;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 20),
      decoration: const BoxDecoration(
        color: Color(0xFF0B1120),
        borderRadius: BorderRadius.vertical(top: Radius.circular(22)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Multi-Chain Sovereign Vault',
                    style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  Text(
                    'Hardware Encrypted BIP-39 • Read-Only Receive',
                    style: TextStyle(color: Color(0xFF00E5A0), fontSize: 11),
                  ),
                ],
              ),
              IconButton(
                onPressed: _loadVault,
                icon: const Icon(Icons.refresh, color: Colors.white70),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (_loading)
            const Padding(
              padding: EdgeInsets.all(28),
              child: CircularProgressIndicator(color: Color(0xFF00E5A0)),
            )
          else if (_error != null)
            Text(_error!, style: const TextStyle(color: Colors.redAccent))
          else
            ..._balances.map((item) {
              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF131C31),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFF1E293B)),
                ),
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 18,
                      backgroundColor: const Color(0xFF1E293B),
                      child: Text(
                        item.symbol,
                        style: const TextStyle(color: Colors.amber, fontSize: 10, fontWeight: FontWeight.bold),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            '${item.chainName} (${item.status})',
                            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            '${item.address.substring(0, 10)}...${item.address.substring(item.address.length - 8)}',
                            style: const TextStyle(color: Colors.white54, fontSize: 11),
                          ),
                        ],
                      ),
                    ),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Text(
                          '${item.balance} ${item.symbol}',
                          style: const TextStyle(color: Color(0xFF00E5A0), fontWeight: FontWeight.bold, fontSize: 12),
                        ),
                        InkWell(
                          onTap: () {
                            Clipboard.setData(ClipboardData(text: item.address));
                            HapticFeedback.lightImpact();
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('${item.symbol} Receive Address Copied!')),
                            );
                          },
                          child: const Padding(
                            padding: EdgeInsets.only(top: 4),
                            child: Text('Copy Address', style: TextStyle(color: Color(0xFF38BDF8), fontSize: 11)),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              );
            }),
        ],
      ),
    );
  }
}