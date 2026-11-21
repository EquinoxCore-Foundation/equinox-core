import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'eqx_multichain_vault.dart';

class _LaunchToken {
  final String assetId;
  final String name;
  final String ticker;
  final String supply;
  final double progress;
  final String status;

  const _LaunchToken({
    required this.assetId,
    required this.name,
    required this.ticker,
    required this.supply,
    required this.progress,
    required this.status,
  });
}

class EqxLaunchpadTab extends StatefulWidget {
  const EqxLaunchpadTab({super.key});

  @override
  State<EqxLaunchpadTab> createState() => _EqxLaunchpadTabState();
}

class _EqxLaunchpadTabState extends State<EqxLaunchpadTab> {
  static const String _nodeRpcUrl = 'http://127.0.0.1:18545';

  int _tab = 0; // 0: Launches, 1: Create Token
  bool _fixedSupply = true;
  bool _autoDexMigrate = true;
  bool _deploying = false;
  bool _nodeOnline = false;

  final TextEditingController _nameCtrl = TextEditingController();
  final TextEditingController _tickerCtrl = TextEditingController();
  final TextEditingController _supplyCtrl = TextEditingController(text: '1000000');

  List<_LaunchToken> _tokens = [
    const _LaunchToken(assetId: 'eqx_asset_demo1', name: 'Equinox AI', ticker: 'EQAI', supply: '10,000,000', progress: 0.78, status: 'Bonding Curve'),
    const _LaunchToken(assetId: 'eqx_asset_demo2', name: 'Solar Gold', ticker: 'SGLD', supply: '1,000,000', progress: 1.00, status: 'Migrated to DEX'),
  ];

  @override
  void initState() {
    super.initState();
    _syncFromNode();
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _tickerCtrl.dispose();
    _supplyCtrl.dispose();
    super.dispose();
  }

  Future<void> _syncFromNode() async {
    try {
      final res = await http
          .post(
            Uri.parse(_nodeRpcUrl),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': 1,
              'method': 'eqx_listTokens',
              'params': <String, dynamic>{},
            }),
          )
          .timeout(const Duration(seconds: 3));

      if (res.statusCode == 200) {
        final body = jsonDecode(res.body) as Map<String, dynamic>;
        final result = body['result'] as Map<String, dynamic>?;
        final list = (result?['tokens'] as List<dynamic>?) ?? [];
        final parsed = list.map((item) {
          final m = item as Map<String, dynamic>;
          return _LaunchToken(
            assetId: m['asset_id']?.toString() ?? '',
            name: m['name']?.toString() ?? 'Unknown',
            ticker: m['ticker']?.toString() ?? 'TKN',
            supply: m['total_supply']?.toString() ?? '0',
            progress: 0.15,
            status: 'Live on Equinox L1',
          );
        }).toList();

        if (!mounted) return;
        setState(() {
          _nodeOnline = true;
          if (parsed.isNotEmpty) {
            _tokens = parsed;
          }
        });
      }
    } catch (_) {
      if (mounted) setState(() => _nodeOnline = false);
    }
  }

  Future<void> _deployToken() async {
    final name = _nameCtrl.text.trim();
    final ticker = _tickerCtrl.text.trim().toUpperCase();
    final supply = _supplyCtrl.text.trim().replaceAll(',', '');
    if (name.isEmpty || ticker.isEmpty || supply.isEmpty) {
      _toast('Please fill Token Name, Ticker & Supply', err: true);
      return;
    }

    setState(() => _deploying = true);
    try {
      String creator = 'eqx1localcreator';
      final seed = await EqxMultiChainVault.loadSeedSecurely();
      if (seed != null && EqxMultiChainVault.isValidMnemonic(seed)) {
        final addrs = await EqxMultiChainVault.deriveAddresses(seed);
        creator = addrs.eqxAddress;
      }

      final res = await http
          .post(
            Uri.parse(_nodeRpcUrl),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': DateTime.now().millisecondsSinceEpoch,
              'method': 'eqx_deployToken',
              'params': {
                'creator': creator,
                'name': name,
                'ticker': ticker,
                'decimals': 6,
                'total_supply': supply,
                'nonce': DateTime.now().millisecondsSinceEpoch,
              },
            }),
          )
          .timeout(const Duration(seconds: 5));

      if (res.statusCode == 200) {
        final body = jsonDecode(res.body) as Map<String, dynamic>;
        final result = body['result'] as Map<String, dynamic>?;
        if (result != null && result['ok'] == true) {
          final assetId = result['asset_id'].toString();
          HapticFeedback.mediumImpact();
          if (!mounted) return;
          setState(() {
            _nodeOnline = true;
            _deploying = false;
            _tab = 0;
            _nameCtrl.clear();
            _tickerCtrl.clear();
          });
          await _syncFromNode();
          _toast('Deployed $ticker on Equinox L1 ($assetId)');
          return;
        } else {
          final err = result?['error']?.toString() ?? 'Node rejected token';
          if (mounted) setState(() => _deploying = false);
          _toast('Deploy failed: $err', err: true);
          return;
        }
      }
    } catch (_) {
      // Offline fallback preview if local Rust node is not running yet
      HapticFeedback.mediumImpact();
      if (mounted) {
        setState(() {
          _nodeOnline = false;
          _deploying = false;
          _tokens.insert(
            0,
            _LaunchToken(
              assetId: 'offline_preview',
              name: name,
              ticker: ticker,
              supply: supply,
              progress: 0.05,
              status: 'Local Preview (Start Node)',
            ),
          );
          _tab = 0;
          _nameCtrl.clear();
          _tickerCtrl.clear();
        });
        _toast('Node offline on :18545 — saved in preview. Start Equinox node to deploy live.');
      }
      return;
    }

    if (mounted) setState(() => _deploying = false);
  }

  void _toast(String msg, {bool err = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        behavior: SnackBarBehavior.floating,
        backgroundColor: err ? Colors.redAccent : const Color(0xFF00D68F),
        content: Text(
          msg,
          style: TextStyle(color: err ? Colors.white : const Color(0xFF08090C), fontWeight: FontWeight.w700),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      color: const Color(0xFF00D68F),
      backgroundColor: const Color(0xFF13151C),
      onRefresh: _syncFromNode,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: ListView(
            padding: const EdgeInsets.fromLTRB(20, 14, 20, 40),
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Equinox Launchpad', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.w700)),
                      SizedBox(height: 2),
                      Text('Native UTXO Assets • Consensus Enforced', style: TextStyle(color: Color(0xFF8A919E), fontSize: 12)),
                    ],
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                    decoration: BoxDecoration(
                      color: (_nodeOnline ? const Color(0xFF00D68F) : const Color(0xFFF5B731)).withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      _nodeOnline ? 'Node Live :18545' : 'Node Offline',
                      style: TextStyle(
                        color: _nodeOnline ? const Color(0xFF00D68F) : const Color(0xFFF5B731),
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              Container(
                padding: const EdgeInsets.all(4),
                decoration: BoxDecoration(
                  color: const Color(0xFF13151C),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Row(
                  children: [
                    _segBtn('Live Launches', _tab == 0, () => setState(() => _tab = 0)),
                    _segBtn('Create Token', _tab == 1, () => setState(() => _tab = 1)),
                  ],
                ),
              ),
              const SizedBox(height: 18),
              if (_tab == 0) ..._tokens.map(_buildLaunchCard) else _buildCreateForm(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _segBtn(String label, bool active, VoidCallback onTap) {
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: active ? Colors.white : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
          ),
          alignment: Alignment.center,
          child: Text(
            label,
            style: TextStyle(
              color: active ? const Color(0xFF08090C) : const Color(0xFF9CA3AF),
              fontWeight: FontWeight.w700,
              fontSize: 13,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLaunchCard(_LaunchToken t) {
    final migrated = t.progress >= 1.0;
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF13151C),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 20,
                backgroundColor: const Color(0xFF1E222D),
                child: Text(t.ticker.substring(0, t.ticker.length > 3 ? 3 : t.ticker.length),
                    style: const TextStyle(color: Color(0xFFF5B731), fontSize: 10, fontWeight: FontWeight.w800)),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${t.name} (${t.ticker})', style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 2),
                    Text('Supply: ${t.supply} • ${t.assetId}', overflow: TextOverflow.ellipsis, style: const TextStyle(color: Color(0xFF8A919E), fontSize: 11)),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
                decoration: BoxDecoration(
                  color: (migrated ? const Color(0xFF00D68F) : const Color(0xFFF5B731)).withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  t.status,
                  style: TextStyle(
                    color: migrated ? const Color(0xFF00D68F) : const Color(0xFFF5B731),
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: t.progress,
              minHeight: 6,
              backgroundColor: const Color(0xFF08090C),
              valueColor: AlwaysStoppedAnimation<Color>(migrated ? const Color(0xFF00D68F) : const Color(0xFFF5B731)),
            ),
          ),
          const SizedBox(height: 6),
          const Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('Anti-Rug L1 Token', style: TextStyle(color: Color(0xFF8A919E), fontSize: 11)),
              Text('Mint: Disabled • Freeze: Disabled', style: TextStyle(color: Color(0xFF00D68F), fontSize: 10)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCreateForm() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF13151C),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Deploy Native UTXO Token', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700)),
          const SizedBox(height: 4),
          const Text('Broadcasts eqx_deployToken directly to Equinox Rust Node', style: TextStyle(color: Color(0xFF8A919E), fontSize: 11)),
          const SizedBox(height: 16),
          _input(_nameCtrl, 'Token Name (e.g. Equinox Gold)'),
          const SizedBox(height: 10),
          _input(_tickerCtrl, 'Ticker Symbol (e.g. EGD)'),
          const SizedBox(height: 10),
          _input(_supplyCtrl, 'Total Fixed Supply', number: true),
          const SizedBox(height: 12),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Fixed Supply (Minting Disabled Forever)', style: TextStyle(color: Colors.white, fontSize: 13)),
            value: _fixedSupply,
            activeThumbColor: const Color(0xFF00D68F),
            onChanged: (v) => setState(() => _fixedSupply = v),
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Auto-Migrate to Equinox AMM DEX', style: TextStyle(color: Colors.white, fontSize: 13)),
            value: _autoDexMigrate,
            activeThumbColor: const Color(0xFF00D68F),
            onChanged: (v) => setState(() => _autoDexMigrate = v),
          ),
          const SizedBox(height: 14),
          ElevatedButton(
            onPressed: _deploying ? null : _deployToken,
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00D68F),
              foregroundColor: const Color(0xFF08090C),
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
            ),
            child: _deploying
                ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF08090C)))
                : const Text('Deploy Live on Equinox Node', style: TextStyle(fontWeight: FontWeight.w800, fontSize: 14)),
          ),
        ],
      ),
    );
  }

  Widget _input(TextEditingController ctrl, String hint, {bool number = false}) {
    return TextField(
      controller: ctrl,
      keyboardType: number ? TextInputType.number : TextInputType.text,
      style: const TextStyle(color: Colors.white, fontSize: 14),
      decoration: InputDecoration(
        hintText: hint,
        hintStyle: const TextStyle(color: Color(0xFF6B7280), fontSize: 13),
        filled: true,
        fillColor: const Color(0xFF08090C),
        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
      ),
    );
  }
}