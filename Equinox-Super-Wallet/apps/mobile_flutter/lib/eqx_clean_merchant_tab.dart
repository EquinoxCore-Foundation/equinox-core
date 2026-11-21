import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'eqx_multichain_vault.dart';

class EqxCleanMerchantTab extends StatefulWidget {
  const EqxCleanMerchantTab({super.key});

  @override
  State<EqxCleanMerchantTab> createState() => _EqxCleanMerchantTabState();
}

class _EqxCleanMerchantTabState extends State<EqxCleanMerchantTab> {
  String _selectedChain = 'EQX';
  MultiChainAddresses? _addrs;
  bool _checking = false;
  String _lastBalance = '0.000000';

  final TextEditingController _amountCtrl = TextEditingController();
  final TextEditingController _memoCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _initAddresses();
  }

  @override
  void dispose() {
    _amountCtrl.dispose();
    _memoCtrl.dispose();
    super.dispose();
  }

  Future<void> _initAddresses() async {
    String? seed = await EqxMultiChainVault.loadSeedSecurely();
    if (seed == null || !EqxMultiChainVault.isValidMnemonic(seed)) {
      seed = EqxMultiChainVault.generateNewMnemonic();
      await EqxMultiChainVault.saveSeedSecurely(seed);
    }
    final addrs = await EqxMultiChainVault.deriveAddresses(seed);
    if (mounted) setState(() => _addrs = addrs);
  }

  String get _activeAddress {
    if (_addrs == null) return '';
    if (_selectedChain == 'EQX') return _addrs!.eqxAddress;
    if (_selectedChain == 'SOL') return _addrs!.solanaAddress;
    return _addrs!.evmAddress;
  }

  String get _paymentUri {
    final addr = _activeAddress;
    if (addr.isEmpty) return 'equinox:loading';
    final amt = _amountCtrl.text.trim();
    final memo = Uri.encodeComponent(_memoCtrl.text.trim());
    if (_selectedChain == 'EQX') {
      return amt.isEmpty ? 'equinox:$addr' : 'equinox:$addr?amount=$amt${memo.isNotEmpty ? '&memo=$memo' : ''}';
    }
    if (_selectedChain == 'SOL') {
      return amt.isEmpty ? 'solana:$addr' : 'solana:$addr?amount=$amt${memo.isNotEmpty ? '&memo=$memo' : ''}';
    }
    return 'ethereum:$addr';
  }

  Future<void> _checkOnChainPayment() async {
    if (_addrs == null) return;
    setState(() => _checking = true);
    try {
      final list = await EqxMultiChainVault.fetchAllBalances(_addrs!);
      final match = list.where((b) => b.symbol == _selectedChain || (_selectedChain == 'USDC' && b.symbol == 'ETH')).firstOrNull;
      final newBal = match?.balance ?? '0.000000';
      final increased = (double.tryParse(newBal) ?? 0) > (double.tryParse(_lastBalance) ?? 0);
      if (mounted) {
        setState(() {
          _lastBalance = newBal;
          _checking = false;
        });
        if (increased) {
          SystemSound.play(SystemSoundType.alert);
          HapticFeedback.heavyImpact();
        }
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            behavior: SnackBarBehavior.floating,
            content: Text(
              increased
                  ? 'Payment confirmed on-chain: $newBal $_selectedChain'
                  : 'Live balance: $newBal $_selectedChain',
            ),
            backgroundColor: increased ? const Color(0xFF00D68F) : const Color(0xFF1F2430),
          ),
        );
      }
    } catch (_) {
      if (mounted) setState(() => _checking = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 36),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Minimal Network Pills
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: ['EQX', 'USDC', 'ETH', 'SOL'].map((sym) {
                  final active = _selectedChain == sym;
                  return Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 4),
                    child: ChoiceChip(
                      label: Text(
                        sym,
                        style: TextStyle(
                          color: active ? const Color(0xFF08090C) : Colors.white70,
                          fontWeight: FontWeight.w700,
                          fontSize: 12,
                        ),
                      ),
                      selected: active,
                      showCheckmark: false,
                      selectedColor: Colors.white,
                      backgroundColor: const Color(0xFF13151C),
                      side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                      onSelected: (_) => setState(() => _selectedChain = sym),
                    ),
                  );
                }).toList(),
              ),
              const SizedBox(height: 20),

              // Floating Clean QR Card
              Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: const Color(0xFF13151C),
                  borderRadius: BorderRadius.circular(28),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
                ),
                child: Column(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Stack(
                        alignment: Alignment.center,
                        children: [
                          QrImageView(
                            data: _paymentUri,
                            version: QrVersions.auto,
                            size: 210,
                            errorCorrectionLevel: QrErrorCorrectLevel.H,
                            eyeStyle: const QrEyeStyle(eyeShape: QrEyeShape.circle, color: Color(0xFF08090C)),
                            dataModuleStyle: const QrDataModuleStyle(dataModuleShape: QrDataModuleShape.circle, color: Color(0xFF08090C)),
                          ),
                          Container(
                            width: 44,
                            height: 44,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              gradient: const LinearGradient(colors: [Color(0xFFF5B731), Color(0xFF00D68F)]),
                              border: Border.all(color: Colors.white, width: 3.5),
                            ),
                            alignment: Alignment.center,
                            child: Text(
                              _selectedChain,
                              style: const TextStyle(color: Color(0xFF08090C), fontWeight: FontWeight.w900, fontSize: 10),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 18),
                    Text(
                      'Receive $_selectedChain',
                      style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700),
                    ),
                    const SizedBox(height: 8),
                    InkWell(
                      onTap: _activeAddress.isEmpty
                          ? null
                          : () {
                              Clipboard.setData(ClipboardData(text: _activeAddress));
                              HapticFeedback.lightImpact();
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  behavior: SnackBarBehavior.floating,
                                  content: Text('$_selectedChain address copied', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                                  backgroundColor: const Color(0xFF1F2430),
                                ),
                              );
                            },
                      borderRadius: BorderRadius.circular(14),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                        decoration: BoxDecoration(
                          color: const Color(0xFF08090C),
                          borderRadius: BorderRadius.circular(14),
                        ),
                        child: Row(
                          children: [
                            Expanded(
                              child: Text(
                                _activeAddress.isEmpty ? 'Generating...' : _activeAddress,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(color: Color(0xFF9CA3AF), fontSize: 12, fontFamily: 'monospace'),
                              ),
                            ),
                            const SizedBox(width: 8),
                            const Icon(Icons.copy_rounded, size: 15, color: Colors.white70),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _amountCtrl,
                            keyboardType: const TextInputType.numberWithOptions(decimal: true),
                            onChanged: (_) => setState(() {}),
                            style: const TextStyle(color: Colors.white, fontSize: 13),
                            decoration: InputDecoration(
                              hintText: 'Amount (optional)',
                              hintStyle: const TextStyle(color: Color(0xFF6B7280), fontSize: 12),
                              filled: true,
                              fillColor: const Color(0xFF08090C),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: TextField(
                            controller: _memoCtrl,
                            onChanged: (_) => setState(() {}),
                            style: const TextStyle(color: Colors.white, fontSize: 13),
                            decoration: InputDecoration(
                              hintText: 'Note (optional)',
                              hintStyle: const TextStyle(color: Color(0xFF6B7280), fontSize: 12),
                              filled: true,
                              fillColor: const Color(0xFF08090C),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: _checking ? null : _checkOnChainPayment,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.white,
                  foregroundColor: const Color(0xFF08090C),
                  padding: const EdgeInsets.symmetric(vertical: 15),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                ),
                child: _checking
                    ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF08090C)))
                    : const Text('Check Payment Status', style: TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}