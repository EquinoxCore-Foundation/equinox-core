import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'eqx_erc4337_service.dart';

class EqxGaslessUsdcSheet extends StatefulWidget {
  const EqxGaslessUsdcSheet({super.key});

  @override
  State<EqxGaslessUsdcSheet> createState() => _EqxGaslessUsdcSheetState();
}

class _EqxGaslessUsdcSheetState extends State<EqxGaslessUsdcSheet> {
  bool _loading = true;
  bool _sending = false;
  BaseSepoliaState? _state;
  String? _statusMsg;
  String? _lastHash;
  bool _isError = false;

  final TextEditingController _toCtrl = TextEditingController();
  final TextEditingController _amtCtrl = TextEditingController(text: '1.00');
  final TextEditingController _paymasterCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _init();
  }

  @override
  void dispose() {
    _toCtrl.dispose();
    _amtCtrl.dispose();
    _paymasterCtrl.dispose();
    super.dispose();
  }

  Future<void> _init() async {
    setState(() => _loading = true);
    final url = await EqxErc4337Service.loadPaymasterUrl();
    _paymasterCtrl.text = url;
    final st = await EqxErc4337Service.fetchBaseSepoliaState();
    if (!mounted) return;
    setState(() {
      _state = st;
      _loading = false;
    });
  }

  Future<void> _submit() async {
    setState(() {
      _sending = true;
      _statusMsg = null;
      _isError = false;
    });
    try {
      await EqxErc4337Service.savePaymasterUrl(_paymasterCtrl.text);
      final res = await EqxErc4337Service.sendGaslessUsdc(
        recipient: _toCtrl.text,
        amountUsdc: _amtCtrl.text,
        bundlerPaymasterUrl: _paymasterCtrl.text,
      );
      HapticFeedback.mediumImpact();
      if (!mounted) return;
      setState(() {
        _sending = false;
        _statusMsg = res.message;
        _lastHash = res.userOpHash;
        _isError = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _sending = false;
        _statusMsg = e.toString().replaceFirst('Exception: ', '');
        _isError = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.fromLTRB(18, 16, 18, MediaQuery.of(context).viewInsets.bottom + 22),
      decoration: const BoxDecoration(
        color: Color(0xFF090E1A),
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Gasless USDC (Base Sepolia)',
                      style: TextStyle(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold),
                    ),
                    Text(
                      'ERC-4337 v0.7 • Paymaster Sponsored • Zero ETH Needed',
                      style: TextStyle(color: Color(0xFF00E5A0), fontSize: 11),
                    ),
                  ],
                ),
                IconButton(
                  onPressed: _init,
                  icon: const Icon(Icons.refresh, color: Colors.white60, size: 20),
                ),
              ],
            ),
            const SizedBox(height: 12),
            if (_loading)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Center(child: CircularProgressIndicator(color: Color(0xFF00E5A0))),
              )
            else if (_state != null) ...[
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: const Color(0xFF111827),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFF1F2937)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text('Testnet USDC Balance', style: TextStyle(color: Colors.white54, fontSize: 11)),
                        Text(
                          '${_state!.usdcBalance} USDC',
                          style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 15, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    InkWell(
                      onTap: () {
                        Clipboard.setData(ClipboardData(text: _state!.ownerAddress));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Base Sepolia address copied! Use Circle Faucet to get free testnet USDC.')),
                        );
                      },
                      child: Row(
                        children: [
                          Expanded(
                            child: Text(
                              'Address: ${_state!.ownerAddress}',
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(color: Colors.white70, fontSize: 11, fontFamily: 'monospace'),
                            ),
                          ),
                          const Icon(Icons.copy, size: 14, color: Color(0xFF38BDF8)),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _toCtrl,
                style: const TextStyle(color: Colors.white, fontSize: 13),
                decoration: _dec('Recipient 0x Address (Base Sepolia)', Icons.person_outline),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _amtCtrl,
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                decoration: _dec('Amount (USDC)', Icons.payments_outlined),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _paymasterCtrl,
                style: const TextStyle(color: Colors.white70, fontSize: 12),
                decoration: _dec('Bundler/Paymaster RPC URL (Pimlico / CDP Base Sepolia)', Icons.hub_outlined),
              ),
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF111827),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text('Network Gas Fee (ETH)', style: TextStyle(color: Colors.white60, fontSize: 12)),
                    Text('\$0.00 (Paymaster Sponsored)', style: TextStyle(color: Color(0xFF00E5A0), fontSize: 12, fontWeight: FontWeight.bold)),
                  ],
                ),
              ),
              if (_statusMsg != null) ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: (_isError ? Colors.redAccent : const Color(0xFF059669)).withValues(alpha: 0.16),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: _isError ? Colors.redAccent : const Color(0xFF00E5A0)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(_statusMsg!, style: TextStyle(color: _isError ? Colors.redAccent : const Color(0xFF00E5A0), fontSize: 12)),
                      if (_lastHash != null) ...[
                        const SizedBox(height: 4),
                        SelectableText(
                          'UserOp Hash: $_lastHash',
                          style: const TextStyle(color: Colors.white70, fontSize: 10, fontFamily: 'monospace'),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 14),
              ElevatedButton(
                onPressed: _sending ? null : _submit,
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF00E5A0),
                  foregroundColor: const Color(0xFF090E1A),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
                child: _sending
                    ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF090E1A)))
                    : const Text('Sign & Send Gasless USDC', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14)),
              ),
            ],
          ],
        ),
      ),
    );
  }

  InputDecoration _dec(String hint, IconData icon) {
    return InputDecoration(
      prefixIcon: Icon(icon, color: Colors.white54, size: 18),
      hintText: hint,
      hintStyle: const TextStyle(color: Colors.white38, fontSize: 12),
      filled: true,
      fillColor: const Color(0xFF111827),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF1F2937))),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF1F2937))),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF00E5A0))),
    );
  }
}