import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'eqx_i18n.dart';

class EqxEasyPaySheet extends StatefulWidget {
  const EqxEasyPaySheet({super.key});

  @override
  State<EqxEasyPaySheet> createState() => _EqxEasyPaySheetState();
}

class _EqxEasyPaySheetState extends State<EqxEasyPaySheet> {
  int _tab = 0; // 0 = Send, 1 = Pay Link, 2 = Split Bill
  String _asset = 'USDC';
  bool _showFeeDetails = false;
  bool _enableTimeLock = false;
  int _splitPeople = 2;

  final TextEditingController _recipientCtrl = TextEditingController();
  final TextEditingController _amountCtrl = TextEditingController(text: '25.00');
  final TextEditingController _noteCtrl = TextEditingController();
  final TextEditingController _myHandleCtrl = TextEditingController(text: 'user@equinox');
  final TextEditingController _billTotalCtrl = TextEditingController(text: '100.00');

  double get _parsedAmount => double.tryParse(_amountCtrl.text.trim()) ?? 0.0;
  double get _parsedBill => double.tryParse(_billTotalCtrl.text.trim()) ?? 0.0;

  // Transparent Fee Calculation (Paymaster Network Gas + Platform Service Fee)
  double get _networkFee {
    if (_parsedAmount <= 0) return 0.0;
    if (_asset == 'EQX') return 0.0001;
    return 0.015; // Base/Polygon L2 sponsored gas estimate in USD
  }

  double get _serviceFee {
    if (_parsedAmount <= 0) return 0.0;
    // 0.10% capped at $0.50, min $0.01 (zero hidden spread)
    final raw = _parsedAmount * 0.001;
    return raw.clamp(0.01, 0.50);
  }

  double get _totalFee => _networkFee + _serviceFee;

  @override
  void dispose() {
    _recipientCtrl.dispose();
    _amountCtrl.dispose();
    _noteCtrl.dispose();
    _myHandleCtrl.dispose();
    _billTotalCtrl.dispose();
    super.dispose();
  }

  void _toast(String msg, {bool isError = false}) {
    HapticFeedback.mediumImpact();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: isError ? Colors.redAccent : const Color(0xFF059669),
      ),
    );
  }

  String _buildPayLink(double amount, String note) {
    final handle = _myHandleCtrl.text.trim().isEmpty ? 'user@equinox' : _myHandleCtrl.text.trim();
    final safeNote = Uri.encodeComponent(note.trim());
    return 'https://pay.equinox.app/$handle?asset=$_asset&amt=${amount.toStringAsFixed(2)}&note=$safeNote';
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<String>(
      valueListenable: EqxI18n.localeNotifier,
      builder: (context, lang, _) {
        return Directionality(
          textDirection: EqxI18n.isRtl ? TextDirection.rtl : TextDirection.ltr,
          child: Container(
            padding: EdgeInsets.fromLTRB(
              18,
              14,
              18,
              MediaQuery.of(context).viewInsets.bottom + 20,
            ),
            decoration: const BoxDecoration(
              color: Color(0xFF090E1A),
              borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
            ),
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      decoration: BoxDecoration(
                        color: Colors.white24,
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              EqxI18n.t('title'),
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 18,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            Text(
                              EqxI18n.t('subtitle'),
                              style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 11),
                            ),
                          ],
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
                        decoration: BoxDecoration(
                          color: const Color(0xFF141D30),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: const Color(0xFF23304A)),
                        ),
                        child: DropdownButton<String>(
                          value: lang,
                          dropdownColor: const Color(0xFF141D30),
                          underline: const SizedBox.shrink(),
                          icon: const Icon(Icons.language, color: Color(0xFF00E5A0), size: 16),
                          style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600),
                          items: EqxI18n.supportedLanguages.entries
                              .map((e) => DropdownMenuItem(value: e.key, child: Text(e.value)))
                              .toList(),
                          onChanged: (v) {
                            if (v != null) EqxI18n.setLanguage(v);
                          },
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  // Asset Selector (Default Stablecoin USDC / USDT / EQX)
                  Row(
                    children: ['USDC', 'USDT', 'EQX'].map((sym) {
                      final active = _asset == sym;
                      return Expanded(
                        child: GestureDetector(
                          onTap: () => setState(() => _asset = sym),
                          child: Container(
                            margin: const EdgeInsets.symmetric(horizontal: 4),
                            padding: const EdgeInsets.symmetric(vertical: 8),
                            decoration: BoxDecoration(
                              color: active ? const Color(0xFF00E5A0).withValues(alpha: 0.16) : const Color(0xFF111827),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(
                                color: active ? const Color(0xFF00E5A0) : const Color(0xFF1F2937),
                              ),
                            ),
                            alignment: Alignment.center,
                            child: Text(
                              sym,
                              style: TextStyle(
                                color: active ? const Color(0xFF00E5A0) : Colors.white60,
                                fontWeight: FontWeight.bold,
                                fontSize: 12,
                              ),
                            ),
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                  const SizedBox(height: 12),
                  // Mode Tabs
                  Container(
                    padding: const EdgeInsets.all(4),
                    decoration: BoxDecoration(
                      color: const Color(0xFF111827),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Row(
                      children: [
                        _tabBtn(0, EqxI18n.t('tab_send')),
                        _tabBtn(1, EqxI18n.t('tab_link')),
                        _tabBtn(2, EqxI18n.t('tab_split')),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                  if (_tab == 0) _buildSendView(),
                  if (_tab == 1) _buildLinkView(),
                  if (_tab == 2) _buildSplitView(),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _tabBtn(int idx, String label) {
    final active = _tab == idx;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _tab = idx),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: active ? const Color(0xFF00E5A0) : Colors.transparent,
            borderRadius: BorderRadius.circular(9),
          ),
          alignment: Alignment.center,
          child: Text(
            label,
            style: TextStyle(
              color: active ? const Color(0xFF090E1A) : Colors.white60,
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSendView() {
    final hasRecipient = _recipientCtrl.text.trim().isNotEmpty;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _recipientCtrl,
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white, fontSize: 14),
          decoration: _inputDec(EqxI18n.t('recipient_hint'), Icons.alternate_email),
        ),
        if (hasRecipient) ...[
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFFF59E0B).withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFFF59E0B).withValues(alpha: 0.4)),
            ),
            child: Row(
              children: [
                const Icon(Icons.warning_amber_rounded, color: Color(0xFFF59E0B), size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    EqxI18n.t('new_recipient_warn'),
                    style: const TextStyle(color: Color(0xFFFCD34D), fontSize: 11),
                  ),
                ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 10),
        TextField(
          controller: _amountCtrl,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
          decoration: _inputDec('${EqxI18n.t('amount_label')} ($_asset)', Icons.payments_outlined),
        ),
        const SizedBox(height: 10),
        // Transparent Fee Breakdown Box (Single Total -> Tap to Expand)
        InkWell(
          onTap: () => setState(() => _showFeeDetails = !_showFeeDetails),
          borderRadius: BorderRadius.circular(14),
          child: Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: const Color(0xFF111827),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0xFF1F2937)),
            ),
            child: Column(
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          EqxI18n.t('total_fee'),
                          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13),
                        ),
                        Text(
                          EqxI18n.t('tap_details'),
                          style: const TextStyle(color: Color(0xFF38BDF8), fontSize: 10),
                        ),
                      ],
                    ),
                    Row(
                      children: [
                        Text(
                          '${_totalFee.toStringAsFixed(4)} $_asset',
                          style: const TextStyle(color: Color(0xFF00E5A0), fontWeight: FontWeight.bold, fontSize: 13),
                        ),
                        const SizedBox(width: 4),
                        Icon(
                          _showFeeDetails ? Icons.expand_less : Icons.expand_more,
                          color: Colors.white54,
                          size: 18,
                        ),
                      ],
                    ),
                  ],
                ),
                if (_showFeeDetails) ...[
                  const Divider(color: Colors.white12, height: 18),
                  _feeRow(EqxI18n.t('net_fee'), '${_networkFee.toStringAsFixed(4)} $_asset'),
                  const SizedBox(height: 6),
                  _feeRow(EqxI18n.t('svc_fee'), '${_serviceFee.toStringAsFixed(4)} $_asset'),
                  const Divider(color: Colors.white12, height: 16),
                  _feeRow(
                    EqxI18n.t('total_pay'),
                    '${(_parsedAmount + _totalFee).toStringAsFixed(4)} $_asset',
                    bold: true,
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 8),
        Material(
          color: Colors.transparent,
          child: SwitchListTile(
            contentPadding: EdgeInsets.zero,
            activeThumbColor: const Color(0xFF00E5A0),
            value: _enableTimeLock,
            onChanged: (v) => setState(() => _enableTimeLock = v),
            title: Text(
              EqxI18n.t('timelock_label'),
              style: const TextStyle(color: Colors.white70, fontSize: 12),
            ),
          ),
        ),
        const SizedBox(height: 8),
        ElevatedButton(
          onPressed: () {
            if (_recipientCtrl.text.trim().isEmpty) {
              _toast(EqxI18n.t('invalid_rec'), isError: true);
              return;
            }
            if (_parsedAmount <= 0) {
              _toast(EqxI18n.t('invalid_amt'), isError: true);
              return;
            }
            SystemSound.play(SystemSoundType.click);
            _toast(EqxI18n.t('send_done'));
          },
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00E5A0),
            foregroundColor: const Color(0xFF090E1A),
            padding: const EdgeInsets.symmetric(vertical: 15),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          ),
          child: Text(
            EqxI18n.t('send_btn'),
            style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
          ),
        ),
      ],
    );
  }

  Widget _buildLinkView() {
    final link = _buildPayLink(_parsedAmount, _noteCtrl.text);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _myHandleCtrl,
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white),
          decoration: _inputDec(EqxI18n.t('your_handle'), Icons.person_outline),
        ),
        const SizedBox(height: 10),
        TextField(
          controller: _amountCtrl,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
          decoration: _inputDec('${EqxI18n.t('amount_label')} ($_asset)', Icons.attach_money),
        ),
        const SizedBox(height: 10),
        TextField(
          controller: _noteCtrl,
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white),
          decoration: _inputDec(EqxI18n.t('note_hint'), Icons.edit_note),
        ),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFF111827),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF00E5A0).withValues(alpha: 0.4)),
          ),
          child: SelectableText(
            link,
            style: const TextStyle(color: Color(0xFF38BDF8), fontSize: 12),
          ),
        ),
        const SizedBox(height: 14),
        ElevatedButton.icon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: link));
            _toast(EqxI18n.t('link_copied'));
          },
          icon: const Icon(Icons.copy, size: 18),
          label: Text(EqxI18n.t('gen_link_btn'), style: const TextStyle(fontWeight: FontWeight.bold)),
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00E5A0),
            foregroundColor: const Color(0xFF090E1A),
            padding: const EdgeInsets.symmetric(vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          ),
        ),
      ],
    );
  }

  Widget _buildSplitView() {
    final share = _splitPeople > 0 ? (_parsedBill / _splitPeople) : 0.0;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _billTotalCtrl,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
          decoration: _inputDec('${EqxI18n.t('total_bill')} ($_asset)', Icons.receipt_long),
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              '${EqxI18n.t('people_count')}: $_splitPeople',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
            ),
            Row(
              children: [
                IconButton(
                  onPressed: _splitPeople > 2 ? () => setState(() => _splitPeople--) : null,
                  icon: const Icon(Icons.remove_circle_outline, color: Colors.white70),
                ),
                IconButton(
                  onPressed: _splitPeople < 20 ? () => setState(() => _splitPeople++) : null,
                  icon: const Icon(Icons.add_circle_outline, color: Color(0xFF00E5A0)),
                ),
              ],
            ),
          ],
        ),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0xFF111827),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: const Color(0xFF1F2937)),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(EqxI18n.t('per_person'), style: const TextStyle(color: Colors.white70)),
              Text(
                '${share.toStringAsFixed(2)} $_asset',
                style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 20, fontWeight: FontWeight.bold),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        ElevatedButton.icon(
          onPressed: () {
            if (_parsedBill <= 0) {
              _toast(EqxI18n.t('invalid_amt'), isError: true);
              return;
            }
            final splitLink = _buildPayLink(share, 'Split Bill ($_splitPeople people)');
            final msg = 'Split Bill: ${share.toStringAsFixed(2)} $_asset each -> $splitLink';
            Clipboard.setData(ClipboardData(text: msg));
            _toast(EqxI18n.t('split_copied'));
          },
          icon: const Icon(Icons.call_split, size: 18),
          label: Text(EqxI18n.t('copy_split'), style: const TextStyle(fontWeight: FontWeight.bold)),
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00E5A0),
            foregroundColor: const Color(0xFF090E1A),
            padding: const EdgeInsets.symmetric(vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          ),
        ),
      ],
    );
  }

  Widget _feeRow(String label, String value, {bool bold = false}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              color: bold ? Colors.white : Colors.white60,
              fontSize: 12,
              fontWeight: bold ? FontWeight.bold : FontWeight.normal,
            ),
          ),
        ),
        Text(
          value,
          style: TextStyle(
            color: bold ? const Color(0xFF00E5A0) : Colors.white,
            fontSize: 12,
            fontWeight: bold ? FontWeight.bold : FontWeight.w500,
          ),
        ),
      ],
    );
  }

  InputDecoration _inputDec(String hint, IconData icon) {
    return InputDecoration(
      prefixIcon: Icon(icon, color: Colors.white54, size: 18),
      hintText: hint,
      hintStyle: const TextStyle(color: Colors.white38, fontSize: 12),
      filled: true,
      fillColor: const Color(0xFF111827),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: Color(0xFF1F2937)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: Color(0xFF1F2937)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: Color(0xFF00E5A0)),
      ),
    );
  }
}