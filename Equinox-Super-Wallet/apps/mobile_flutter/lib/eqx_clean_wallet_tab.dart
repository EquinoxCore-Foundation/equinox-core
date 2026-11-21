import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'eqx_clean_merchant_tab.dart';
import 'eqx_easy_pay_sheet.dart';
import 'eqx_gasless_usdc_sheet.dart';
import 'eqx_multichain_vault.dart';

class EqxCleanWalletTab extends StatefulWidget {
  const EqxCleanWalletTab({super.key});

  @override
  State<EqxCleanWalletTab> createState() => _EqxCleanWalletTabState();
}

class _EqxCleanWalletTabState extends State<EqxCleanWalletTab> {
  bool _loading = true;
  bool _hideBalance = false;
  MultiChainAddresses? _addrs;
  List<ChainBalance> _balances = [];

  @override
  void initState() {
    super.initState();
    _loadRealVault();
  }

  Future<void> _loadRealVault() async {
    setState(() => _loading = true);
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
        _addrs = addrs;
        _balances = list;
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _copy(String label, String value) {
    Clipboard.setData(ClipboardData(text: value));
    HapticFeedback.lightImpact();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
        behavior: SnackBarBehavior.floating,
        backgroundColor: const Color(0xFF1F2430),
      ),
    );
  }

  Color _coinColor(String sym) {
    switch (sym) {
      case 'EQX':
        return const Color(0xFFF5B731);
      case 'ETH':
        return const Color(0xFF627EEA);
      case 'BNB':
        return const Color(0xFFF3BA2F);
      case 'POL':
        return const Color(0xFF8247E5);
      case 'SOL':
        return const Color(0xFF14F195);
      default:
        return const Color(0xFF00D68F);
    }
  }

  @override
  Widget build(BuildContext context) {
    final eqxBal = _balances.where((b) => b.symbol == 'EQX').firstOrNull?.balance ?? '0.0000';
    final eqxAddr = _addrs?.eqxAddress ?? '';
    final shortAddr = eqxAddr.length > 14
        ? '${eqxAddr.substring(0, 6)}...${eqxAddr.substring(eqxAddr.length - 4)}'
        : 'Syncing...';

    return RefreshIndicator(
      color: const Color(0xFF00D68F),
      backgroundColor: const Color(0xFF13151C),
      onRefresh: _loadRealVault,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: ListView(
            padding: const EdgeInsets.fromLTRB(20, 14, 20, 40),
            children: [
              // Clean Hero Balance Section (Phantom / OKX Style)
              Row(
                children: [
                  const Text(
                    'Total Balance',
                    style: TextStyle(color: Color(0xFF8A919E), fontSize: 13, fontWeight: FontWeight.w500),
                  ),
                  const SizedBox(width: 8),
                  GestureDetector(
                    onTap: () => setState(() => _hideBalance = !_hideBalance),
                    child: Icon(
                      _hideBalance ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                      color: const Color(0xFF8A919E),
                      size: 16,
                    ),
                  ),
                  const Spacer(),
                  if (eqxAddr.isNotEmpty)
                    InkWell(
                      onTap: () => _copy('EQX Address', eqxAddr),
                      borderRadius: BorderRadius.circular(20),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                        decoration: BoxDecoration(
                          color: const Color(0xFF13151C),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Row(
                          children: [
                            Text(shortAddr, style: const TextStyle(color: Color(0xFF9CA3AF), fontSize: 11, fontFamily: 'monospace')),
                            const SizedBox(width: 5),
                            const Icon(Icons.copy_rounded, size: 12, color: Color(0xFF9CA3AF)),
                          ],
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 10),
              Text(
                _loading
                    ? '••••••'
                    : _hideBalance
                        ? '•••••• EQX'
                        : '$eqxBal EQX',
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 36,
                  fontWeight: FontWeight.w700,
                  letterSpacing: -0.8,
                ),
              ),
              const SizedBox(height: 24),

              // 4 Sleek Quick Action Buttons (Phantom / OKX Style)
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  _quickAction(
                    icon: Icons.arrow_upward_rounded,
                    label: 'Send',
                    highlight: true,
                    onTap: () {
                      showModalBottomSheet<void>(
                        context: context,
                        isScrollControlled: true,
                        backgroundColor: Colors.transparent,
                        builder: (_) => const EqxEasyPaySheet(),
                      );
                    },
                  ),
                  _quickAction(
                    icon: Icons.arrow_downward_rounded,
                    label: 'Receive',
                    onTap: () {
                      showModalBottomSheet<void>(
                        context: context,
                        isScrollControlled: true,
                        backgroundColor: const Color(0xFF08090C),
                        shape: const RoundedRectangleBorder(
                          borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
                        ),
                        builder: (ctx) => SizedBox(
                          height: MediaQuery.of(ctx).size.height * 0.85,
                          child: Column(
                            children: [
                              const SizedBox(height: 10),
                              Container(
                                width: 42,
                                height: 4,
                                decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(4)),
                              ),
                              const Expanded(child: EqxCleanMerchantTab()),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
                  _quickAction(
                    icon: Icons.bolt_rounded,
                    label: 'Gasless',
                    accent: const Color(0xFF38BDF8),
                    onTap: () {
                      showModalBottomSheet<void>(
                        context: context,
                        isScrollControlled: true,
                        backgroundColor: Colors.transparent,
                        builder: (_) => const EqxGaslessUsdcSheet(),
                      );
                    },
                  ),
                  _quickAction(
                    icon: Icons.refresh_rounded,
                    label: 'Refresh',
                    onTap: _loadRealVault,
                  ),
                ],
              ),
              const SizedBox(height: 30),

              // Section Header
              const Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Crypto',
                    style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700),
                  ),
                  Text(
                    'Live Networks',
                    style: TextStyle(color: Color(0xFF6B7280), fontSize: 12),
                  ),
                ],
              ),
              const SizedBox(height: 12),

              // Clean Minimalist Asset List
              if (_loading)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 48),
                  child: Center(child: CircularProgressIndicator(color: Color(0xFF00D68F), strokeWidth: 2.5)),
                )
              else
                Container(
                  decoration: BoxDecoration(
                    color: const Color(0xFF13151C),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                  ),
                  child: Column(
                    children: List.generate(_balances.length, (i) {
                      final item = _balances[i];
                      final isLast = i == _balances.length - 1;
                      final col = _coinColor(item.symbol);
                      return Column(
                        children: [
                          InkWell(
                            onTap: () => _copy('${item.symbol} Address', item.address),
                            borderRadius: BorderRadius.circular(20),
                            child: Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 15),
                              child: Row(
                                children: [
                                  Container(
                                    width: 40,
                                    height: 40,
                                    decoration: BoxDecoration(
                                      color: col.withValues(alpha: 0.14),
                                      shape: BoxShape.circle,
                                    ),
                                    alignment: Alignment.center,
                                    child: Text(
                                      item.symbol,
                                      style: TextStyle(color: col, fontSize: 11, fontWeight: FontWeight.w800),
                                    ),
                                  ),
                                  const SizedBox(width: 14),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          item.chainName,
                                          style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600),
                                        ),
                                        const SizedBox(height: 3),
                                        Text(
                                          item.status,
                                          style: const TextStyle(color: Color(0xFF6B7280), fontSize: 11),
                                        ),
                                      ],
                                    ),
                                  ),
                                  Column(
                                    crossAxisAlignment: CrossAxisAlignment.end,
                                    children: [
                                      Text(
                                        _hideBalance ? '••••' : '${item.balance} ${item.symbol}',
                                        style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600),
                                      ),
                                      const SizedBox(height: 3),
                                      const Text(
                                        'Tap to copy',
                                        style: TextStyle(color: Color(0xFF6B7280), fontSize: 10),
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ),
                          if (!isLast)
                            Divider(height: 1, indent: 70, endIndent: 16, color: Colors.white.withValues(alpha: 0.05)),
                        ],
                      );
                    }),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _quickAction({
    required IconData icon,
    required String label,
    VoidCallback? onTap,
    bool highlight = false,
    Color? accent,
  }) {
    final bg = highlight ? const Color(0xFF00D68F) : const Color(0xFF13151C);
    final fg = highlight ? const Color(0xFF08090C) : (accent ?? Colors.white);
    return Expanded(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 5),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(18),
          child: Container(
            padding: const EdgeInsets.symmetric(vertical: 14),
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(18),
              border: highlight ? null : Border.all(color: Colors.white.withValues(alpha: 0.06)),
            ),
            child: Column(
              children: [
                Icon(icon, color: fg, size: 22),
                const SizedBox(height: 6),
                Text(
                  label,
                  style: TextStyle(
                    color: highlight ? const Color(0xFF08090C) : const Color(0xFFD1D5DB),
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}