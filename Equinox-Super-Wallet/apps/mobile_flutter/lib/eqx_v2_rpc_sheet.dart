import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'eqx_multichain_sheet.dart';

class EqxV2RpcClient {
  final String endpointUrl;

  const EqxV2RpcClient(this.endpointUrl);

  static String normalizeEndpoint(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty || trimmed.contains(' ')) {
      return 'http://127.0.0.1:8545';
    }
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return trimmed;
    }
    if (trimmed.contains(':')) {
      return 'http://$trimmed';
    }
    return 'http://$trimmed:8545';
  }
  Future<Map<String, dynamic>> call(String method, List<dynamic> params) async {
    final uri = Uri.parse(normalizeEndpoint(endpointUrl));
    final response = await http
        .post(
          uri,
          headers: const {'Content-Type': 'application/json'},
          body: jsonEncode({
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': DateTime.now().millisecondsSinceEpoch,
          }),
        )
        .timeout(const Duration(seconds: 6));

    if (response.statusCode != 200) {
      throw Exception('HTTP ${response.statusCode}: ${response.body}');
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map<String, dynamic>) {
      throw Exception('Invalid JSON-RPC response');
    }
    if (decoded['error'] != null) {
      final err = decoded['error'];
      final msg = err is Map ? (err['message'] ?? err.toString()) : err.toString();
      throw Exception(msg.toString());
    }
    final result = decoded['result'];
    if (result is Map<String, dynamic>) {
      return result;
    }
    return {'value': result};
  }
}

class EqxV2QuickBar extends StatelessWidget {
  final String activeRpcEndpoint;

  const EqxV2QuickBar({
    super.key,
    required this.activeRpcEndpoint,
  });

  void _openSheet(BuildContext context, int initialTab) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF0D1117),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (_) => EqxV2UtilitySheet(
        initialEndpoint: activeRpcEndpoint,
        initialTab: initialTab,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: const BoxDecoration(
        color: Color(0xFF0B1220),
        border: Border(
          top: BorderSide(color: Color(0xFF1E293B), width: 1),
        ),
      ),
      child: Row(
        children: [
          _pill(
            context: context,
            icon: Icons.alternate_email_rounded,
            label: '@name.eqx',
            color: const Color(0xFF00E5A0),
            tab: 0,
          ),
          const SizedBox(width: 8),
          _pill(
            context: context,
            icon: Icons.verified_user_outlined,
            label: 'Verify Proof',
            color: const Color(0xFF38BDF8),
            tab: 1,
          ),
          const SizedBox(width: 8),
          _pill(
            context: context,
            icon: Icons.hub_outlined,
            label: 'Multi-Chain',
            color: const Color(0xFFF59E0B),
            tab: 2,
          ),
        ],
      ),
    );
  }

  Widget _pill({
    required BuildContext context,
    required IconData icon,
    required String label,
    required Color color,
    required int tab,
  }) {
    return Expanded(
      child: InkWell(
        onTap: () { if (tab == 2) { showModalBottomSheet<void>(context: context, isScrollControlled: true, backgroundColor: Colors.transparent, builder: (_) => const EqxMultiChainSheet()); } else { _openSheet(context, tab); } },
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 7),
          decoration: BoxDecoration(
            color: const Color(0xFF131C2E),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: color.withValues(alpha: 0.35)),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 14, color: color),
              const SizedBox(width: 5),
              Flexible(
                child: Text(
                  label,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: color,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class EqxV2UtilitySheet extends StatefulWidget {
  final String initialEndpoint;
  final int initialTab;

  const EqxV2UtilitySheet({
    super.key,
    required this.initialEndpoint,
    this.initialTab = 0,
  });

  @override
  State<EqxV2UtilitySheet> createState() => _EqxV2UtilitySheetState();
}

class _EqxV2UtilitySheetState extends State<EqxV2UtilitySheet> {
  late int _tabIndex;
  late TextEditingController _rpcCtrl;
  final TextEditingController _nameCtrl = TextEditingController(text: '@alice_dev.eqx');
  final TextEditingController _proofCtrl = TextEditingController();
  final TextEditingController _rawTxCtrl = TextEditingController();

  bool _loading = false;
  String? _errorText;
  Map<String, dynamic>? _nameResult;
  Map<String, dynamic>? _proofResult;
  Map<String, dynamic>? _metricsResult;
  Map<String, dynamic>? _txResult;

  @override
  void initState() {
    super.initState();
    _tabIndex = widget.initialTab;
    _rpcCtrl = TextEditingController(
      text: EqxV2RpcClient.normalizeEndpoint(widget.initialEndpoint),
    );
    if (_tabIndex == 2) {
      _loadMetrics();
    }
  }

  @override
  void dispose() {
    _rpcCtrl.dispose();
    _nameCtrl.dispose();
    _proofCtrl.dispose();
    _rawTxCtrl.dispose();
    super.dispose();
  }

  EqxV2RpcClient get _client => EqxV2RpcClient(_rpcCtrl.text);

  Future<void> _lookupNameOrAddress() async {
    final query = _nameCtrl.text.trim();
    if (query.isEmpty) return;
    setState(() {
      _loading = true;
      _errorText = null;
      _nameResult = null;
    });
    try {
      Map<String, dynamic> res;
      if (query.startsWith('@') || query.endsWith('.eqx')) {
        res = await _client.call('eqx_resolveName', [query]);
      } else {
        final bal = await _client.call('eqx_getBalance', [query]);
        res = {
          'found': true,
          'handle': 'Direct EQX Address',
          'owner_address': bal['address'],
          'balance_eqx': bal['balance_eqx'],
          'balance_atomic': bal['balance_atomic'],
        };
      }
      if (!mounted) return;
      setState(() => _nameResult = res);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorText = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _verifyProof() async {
    final hashHex = _proofCtrl.text.trim();
    if (hashHex.isEmpty) return;
    setState(() {
      _loading = true;
      _errorText = null;
      _proofResult = null;
    });
    try {
      final res = await _client.call('eqx_verifyProof', [hashHex]);
      if (!mounted) return;
      setState(() => _proofResult = res);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorText = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadMetrics() async {
    setState(() {
      _loading = true;
      _errorText = null;
    });
    try {
      final res = await _client.call('eqx_getMetrics', const []);
      if (!mounted) return;
      setState(() => _metricsResult = res);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorText = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _broadcastRawTx() async {
    final rawHex = _rawTxCtrl.text.trim();
    if (rawHex.isEmpty) return;
    setState(() {
      _loading = true;
      _errorText = null;
      _txResult = null;
    });
    try {
      final res = await _client.call('eqx_sendRawTransaction', [rawHex]);
      if (!mounted) return;
      setState(() => _txResult = res);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorText = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final bottomInset = MediaQuery.of(context).viewInsets.bottom;
    return Padding(
      padding: EdgeInsets.fromLTRB(16, 12, 16, 16 + bottomInset),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                margin: const EdgeInsets.only(bottom: 14),
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  'Equinox v2 Live RPC Console',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                IconButton(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.close, color: Colors.white54, size: 20),
                ),
              ],
            ),
            const SizedBox(height: 6),
            TextField(
              controller: _rpcCtrl,
              style: const TextStyle(color: Colors.white, fontSize: 12),
              decoration: _inputDecoration('Node JSON-RPC Endpoint (http://IP:8545)'),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              children: [
                _presetBtn('Localhost', 'http://127.0.0.1:8545'),
                _presetBtn('Android Emulator', 'http://10.0.2.2:8545'),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                _tabBtn(0, '@name.eqx'),
                const SizedBox(width: 6),
                _tabBtn(1, 'Proof Verify'),
                const SizedBox(width: 6),
                _tabBtn(2, 'Metrics & TX'),
              ],
            ),
            const SizedBox(height: 14),
            if (_errorText != null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  color: const Color(0xFF3B1219),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Colors.redAccent),
                ),
                child: Text(
                  _errorText!,
                  style: const TextStyle(color: Colors.redAccent, fontSize: 12),
                ),
              ),
            if (_tabIndex == 0) _buildNameTab(),
            if (_tabIndex == 1) _buildProofTab(),
            if (_tabIndex == 2) _buildMetricsTab(),
          ],
        ),
      ),
    );
  }

  Widget _presetBtn(String label, String url) {
    return ActionChip(
      label: Text(label, style: const TextStyle(color: Colors.white70, fontSize: 11)),
      backgroundColor: const Color(0xFF161B22),
      side: const BorderSide(color: Color(0xFF30363D)),
      onPressed: () => setState(() => _rpcCtrl.text = url),
    );
  }

  Widget _tabBtn(int idx, String label) {
    final active = _tabIndex == idx;
    return Expanded(
      child: GestureDetector(
        onTap: () {
          setState(() {
            _tabIndex = idx;
            _errorText = null;
          });
          if (idx == 2 && _metricsResult == null) {
            _loadMetrics();
          }
        },
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 9),
          decoration: BoxDecoration(
            color: active ? const Color(0xFF00E5A0) : const Color(0xFF161B22),
            borderRadius: BorderRadius.circular(10),
          ),
          alignment: Alignment.center,
          child: Text(
            label,
            style: TextStyle(
              color: active ? Colors.black : Colors.white70,
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildNameTab() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _nameCtrl,
          style: const TextStyle(color: Colors.white, fontSize: 13),
          decoration: _inputDecoration('Enter @handle.eqx or 34-char EQX address'),
        ),
        const SizedBox(height: 10),
        ElevatedButton(
          onPressed: _loading ? null : _lookupNameOrAddress,
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00E5A0),
            foregroundColor: Colors.black,
            padding: const EdgeInsets.symmetric(vertical: 12),
          ),
          child: Text(_loading ? 'Querying Node...' : 'Resolve @name.eqx & Check Balance'),
        ),
        if (_nameResult != null) ...[
          const SizedBox(height: 12),
          _infoCard(
            _nameResult!['found'] == true
                ? {
                    'Handle': '${_nameResult!['handle'] ?? ''}',
                    'Address': '${_nameResult!['owner_address'] ?? ''}',
                    'Balance': '${_nameResult!['balance_eqx'] ?? '0'} EQX',
                    if (_nameResult!['registered_height'] != null)
                      'Registered Block': '#${_nameResult!['registered_height']}',
                    if (_nameResult!['expires_height'] != null)
                      'Expires Block': '#${_nameResult!['expires_height']}',
                  }
                : {
                    'Status': 'Not Registered Yet',
                    'Query': '${_nameResult!['query'] ?? _nameCtrl.text}',
                  },
          ),
        ],
      ],
    );
  }

  Widget _buildProofTab() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _proofCtrl,
          style: const TextStyle(color: Colors.white, fontSize: 12),
          decoration: _inputDecoration('Paste 64-char SHA-256 / pHash hex'),
        ),
        const SizedBox(height: 10),
        ElevatedButton(
          onPressed: _loading ? null : _verifyProof,
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF38BDF8),
            foregroundColor: Colors.black,
            padding: const EdgeInsets.symmetric(vertical: 12),
          ),
          child: Text(_loading ? 'Verifying...' : 'Verify On-Chain Document Proof'),
        ),
        if (_proofResult != null) ...[
          const SizedBox(height: 12),
          _infoCard(
            _proofResult!['verified'] == true
                ? {
                    'Status': 'VERIFIED ON-CHAIN',
                    'Metadata': '${_proofResult!['metadata'] ?? ''}',
                    'Block Height': '#${_proofResult!['block_height']}',
                    'Timestamp (UTC)': '${_proofResult!['timestamp']}',
                    'TXID': '${_proofResult!['txid']}',
                  }
                : {
                    'Status': 'NOT FOUND ON CHAIN',
                    'Hash': '${_proofResult!['doc_hash'] ?? ''}',
                  },
          ),
        ],
      ],
    );
  }

  Widget _buildMetricsTab() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ElevatedButton(
          onPressed: _loading ? null : _loadMetrics,
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFFF59E0B),
            foregroundColor: Colors.black,
            padding: const EdgeInsets.symmetric(vertical: 10),
          ),
          child: Text(_loading ? 'Loading...' : 'Refresh Live Node Metrics'),
        ),
        if (_metricsResult != null) ...[
          const SizedBox(height: 10),
          _infoCard({
            'Network': '${_metricsResult!['network']} (Chain ${_metricsResult!['chain_id']})',
            'Tip Height': '#${_metricsResult!['tip_height']}',
            'Connected Peers': '${_metricsResult!['connected_peers']}',
            'Pending Mempool TXs': '${_metricsResult!['pending_txns']}',
            'Registered @names': '${_metricsResult!['registered_names'] ?? 0}',
            'Anchored Proofs': '${_metricsResult!['anchored_proofs'] ?? 0}',
            'UTXO Count': '${_metricsResult!['utxo_count']}',
          }),
        ],
        const SizedBox(height: 14),
        TextField(
          controller: _rawTxCtrl,
          maxLines: 2,
          style: const TextStyle(color: Colors.white, fontSize: 12),
          decoration: _inputDecoration('Signed v2 Raw TX Hex (eqx_sendRawTransaction)'),
        ),
        const SizedBox(height: 8),
        OutlinedButton(
          onPressed: _loading ? null : _broadcastRawTx,
          style: OutlinedButton.styleFrom(
            foregroundColor: const Color(0xFF00E5A0),
            side: const BorderSide(color: Color(0xFF00E5A0)),
          ),
          child: const Text('Broadcast Signed Raw TX'),
        ),
        if (_txResult != null) ...[
          const SizedBox(height: 10),
          _infoCard({
            'Status': '${_txResult!['status']}',
            'TXID': '${_txResult!['txid']}',
            'Fee (atomic)': '${_txResult!['fee_atomic']}',
          }),
        ],
      ],
    );
  }

  InputDecoration _inputDecoration(String hint) {
    return InputDecoration(
      hintText: hint,
      hintStyle: const TextStyle(color: Colors.white38, fontSize: 12),
      filled: true,
      fillColor: const Color(0xFF161B22),
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: Color(0xFF30363D)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: Color(0xFF30363D)),
      ),
    );
  }

  Widget _infoCard(Map<String, String> rows) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF30363D)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: rows.entries.map((entry) {
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  entry.key,
                  style: const TextStyle(color: Colors.white54, fontSize: 11),
                ),
                SelectableText(
                  entry.value,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }
}