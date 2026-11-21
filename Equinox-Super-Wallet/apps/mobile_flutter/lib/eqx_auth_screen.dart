import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class EqxAuthScreen extends StatefulWidget {
  final void Function(String vaultName, String address) onAuthenticated;

  const EqxAuthScreen({super.key, required this.onAuthenticated});

  @override
  State<EqxAuthScreen> createState() => _EqxAuthScreenState();
}

class _EqxAuthScreenState extends State<EqxAuthScreen> {
  bool _isCreateMode = false;
  final TextEditingController _nameCtrl = TextEditingController(text: 'Main Sovereign Vault');
  final TextEditingController _pinCtrl = TextEditingController();
  final TextEditingController _seedCtrl = TextEditingController();
  String _generatedSeed = '';
  String? _error;

  static const List<String> _wordPool = [
    'equinox', 'quantum', 'cipher', 'sovereign', 'ledger', 'vertex', 'orbit', 'velvet',
    'prism', 'aurora', 'matrix', 'cobalt', 'zephyr', 'nebula', 'titan', 'solstice',
    'vector', 'quartz', 'beacon', 'zenith', 'anchor', 'shield', 'pulse', 'horizon',
  ];

  @override
  void initState() {
    super.initState();
    _regenerateSeed();
  }

  void _regenerateSeed() {
    final rng = Random();
    final words = List.generate(12, (_) => _wordPool[rng.nextInt(_wordPool.length)]);
    setState(() => _generatedSeed = words.join(' '));
  }

  String _deriveDemoAddress(String seed) {
    const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    int hash = 5381;
    for (final code in seed.codeUnits) {
      hash = ((hash << 5) + hash + code) & 0x7FFFFFFF;
    }
    final rng = Random(hash);
    final buf = StringBuffer('E');
    for (int i = 0; i < 33; i++) {
      buf.write(chars[rng.nextInt(chars.length)]);
    }
    return buf.toString();
  }

  void _submit() {
    final pin = _pinCtrl.text.trim();
    if (pin.length < 4) {
      setState(() => _error = 'Please enter at least a 4-digit Vault PIN');
      return;
    }
    if (_isCreateMode) {
      final vName = _nameCtrl.text.trim().isEmpty ? 'Sovereign Vault' : _nameCtrl.text.trim();
      final addr = _deriveDemoAddress(_generatedSeed + pin);
      HapticFeedback.mediumImpact();
      widget.onAuthenticated(vName, addr);
    } else {
      final seedInput = _seedCtrl.text.trim();
      final keySource = seedInput.isEmpty ? 'existing_vault_$pin' : seedInput;
      final addr = _deriveDemoAddress(keySource);
      HapticFeedback.mediumImpact();
      widget.onAuthenticated('Main Sovereign Vault', addr);
    }
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _pinCtrl.dispose();
    _seedCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF070B14),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Center(
                    child: Container(
                      width: 72,
                      height: 72,
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFFF59E0B), Color(0xFF00E5A0)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(20),
                        boxShadow: [
                          BoxShadow(
                            color: const Color(0xFF00E5A0).withValues(alpha: 0.28),
                            blurRadius: 24,
                            spreadRadius: 2,
                          ),
                        ],
                      ),
                      alignment: Alignment.center,
                      child: const Text(
                        'EQX',
                        style: TextStyle(
                          color: Color(0xFF070B14),
                          fontWeight: FontWeight.w900,
                          fontSize: 22,
                          letterSpacing: 1.2,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  const Text(
                    'Equinox Super-Wallet',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'Non-Custodial Layer-1 Vault • Argon2id PoW',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Colors.white54, fontSize: 13),
                  ),
                  const SizedBox(height: 24),
                  Container(
                    padding: const EdgeInsets.all(4),
                    decoration: BoxDecoration(
                      color: const Color(0xFF111827),
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: const Color(0xFF1F2937)),
                    ),
                    child: Row(
                      children: [
                        _modeTab('Login Vault', !_isCreateMode, () {
                          setState(() {
                            _isCreateMode = false;
                            _error = null;
                          });
                        }),
                        _modeTab('Create Account', _isCreateMode, () {
                          setState(() {
                            _isCreateMode = true;
                            _error = null;
                          });
                        }),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),
                  if (_isCreateMode) ...[
                    TextField(
                      controller: _nameCtrl,
                      style: const TextStyle(color: Colors.white),
                      decoration: _dec('Vault Name (e.g. Personal Vault)', Icons.account_balance_wallet_outlined),
                    ),
                    const SizedBox(height: 12),
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: const Color(0xFF0F172A),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: const Color(0xFF00E5A0).withValues(alpha: 0.4)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              const Text(
                                '12-Word Recovery Phrase',
                                style: TextStyle(color: Color(0xFF00E5A0), fontSize: 12, fontWeight: FontWeight.bold),
                              ),
                              InkWell(
                                onTap: _regenerateSeed,
                                child: const Icon(Icons.refresh, color: Colors.white70, size: 18),
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          SelectableText(
                            _generatedSeed,
                            style: const TextStyle(color: Colors.white, fontSize: 13, height: 1.5),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                  ] else ...[
                    TextField(
                      controller: _seedCtrl,
                      maxLines: 2,
                      style: const TextStyle(color: Colors.white, fontSize: 13),
                      decoration: _dec('12-Word Seed Phrase (Optional for Quick PIN Login)', Icons.key_outlined),
                    ),
                    const SizedBox(height: 12),
                  ],
                  TextField(
                    controller: _pinCtrl,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    style: const TextStyle(color: Colors.white, letterSpacing: 4),
                    decoration: _dec('Enter Vault PIN (min 4 digits)', Icons.lock_outline),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 10),
                    Text(_error!, style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
                  ],
                  const SizedBox(height: 20),
                  ElevatedButton(
                    onPressed: _submit,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF00E5A0),
                      foregroundColor: const Color(0xFF070B14),
                      padding: const EdgeInsets.symmetric(vertical: 15),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                    ),
                    child: Text(
                      _isCreateMode ? 'Create Sovereign Vault' : 'Unlock & Login',
                      style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _modeTab(String label, bool active, VoidCallback onTap) {
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 11),
          decoration: BoxDecoration(
            color: active ? const Color(0xFF00E5A0) : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
          ),
          alignment: Alignment.center,
          child: Text(
            label,
            style: TextStyle(
              color: active ? const Color(0xFF070B14) : Colors.white60,
              fontWeight: FontWeight.bold,
              fontSize: 13,
            ),
          ),
        ),
      ),
    );
  }

  InputDecoration _dec(String hint, IconData icon) {
    return InputDecoration(
      prefixIcon: Icon(icon, color: Colors.white54, size: 19),
      hintText: hint,
      hintStyle: const TextStyle(color: Colors.white38, fontSize: 12),
      filled: true,
      fillColor: const Color(0xFF111827),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: Color(0xFF1F2937)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: Color(0xFF1F2937)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: Color(0xFF00E5A0)),
      ),
    );
  }
}