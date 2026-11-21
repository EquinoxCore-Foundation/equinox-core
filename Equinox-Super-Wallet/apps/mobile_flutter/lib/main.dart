import 'package:flutter/material.dart';
import 'eqx_auth_screen.dart';
import 'eqx_clean_merchant_tab.dart';
import 'eqx_clean_wallet_tab.dart';
import 'eqx_i18n.dart';
import 'eqx_launchpad_tab.dart';
import 'eqx_live_market.dart';

void main() {
  runApp(const EquinoxSuperWalletApp());
}

class EquinoxSuperWalletApp extends StatelessWidget {
  const EquinoxSuperWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Equinox Wallet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF08090C),
        cardColor: const Color(0xFF13151C),
        dividerColor: Colors.white.withValues(alpha: 0.06),
        colorScheme: const ColorScheme.dark(
          surface: Color(0xFF13151C),
          primary: Color(0xFF00D68F),
          secondary: Color(0xFFF5B731),
        ),
        splashFactory: InkSparkle.splashFactory,
      ),
      home: const _EqxRootGate(),
    );
  }
}

class _EqxRootGate extends StatefulWidget {
  const _EqxRootGate();

  @override
  State<_EqxRootGate> createState() => _EqxRootGateState();
}

class _EqxRootGateState extends State<_EqxRootGate> {
  bool _unlocked = false;
  String _vaultName = 'Main Vault';
  String _vaultAddress = '';

  @override
  Widget build(BuildContext context) {
    if (!_unlocked) {
      return EqxAuthScreen(
        onAuthenticated: (name, addr) {
          setState(() {
            _vaultName = name;
            _vaultAddress = addr;
            _unlocked = true;
          });
        },
      );
    }
    return EquinoxCleanShell(
      vaultName: _vaultName,
      vaultAddress: _vaultAddress,
      onSignOut: () => setState(() => _unlocked = false),
    );
  }
}

class EquinoxCleanShell extends StatefulWidget {
  final String vaultName;
  final String vaultAddress;
  final VoidCallback onSignOut;

  const EquinoxCleanShell({
    super.key,
    required this.vaultName,
    required this.vaultAddress,
    required this.onSignOut,
  });

  @override
  State<EquinoxCleanShell> createState() => _EquinoxCleanShellState();
}

class _EquinoxCleanShellState extends State<EquinoxCleanShell> {
  int _index = 0;

  static const List<Widget> _pages = [
    EqxCleanWalletTab(),
    EqxLiveMarketTab(),
    EqxLaunchpadTab(),
  ];

  void _openMerchantPos() {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF08090C),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (ctx) => SizedBox(
        height: MediaQuery.of(ctx).size.height * 0.86,
        child: Column(
          children: [
            const SizedBox(height: 10),
            Container(
              width: 42,
              height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(4)),
            ),
            const Padding(
              padding: EdgeInsets.only(top: 12),
              child: Text(
                'Merchant POS Terminal',
                style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700),
              ),
            ),
            const Expanded(child: EqxCleanMerchantTab()),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<String>(
      valueListenable: EqxI18n.localeNotifier,
      builder: (context, _, __) {
        return Scaffold(
          backgroundColor: const Color(0xFF08090C),
          appBar: AppBar(
            backgroundColor: const Color(0xFF08090C),
            surfaceTintColor: Colors.transparent,
            elevation: 0,
            toolbarHeight: 62,
            titleSpacing: 16,
            title: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: const Color(0xFF13151C),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(color: Colors.white.withValues(alpha: 0.07)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 24,
                    height: 24,
                    decoration: const BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: LinearGradient(
                        colors: [Color(0xFFF5B731), Color(0xFF00D68F)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                    ),
                    alignment: Alignment.center,
                    child: const Text(
                      'E',
                      style: TextStyle(
                        color: Color(0xFF08090C),
                        fontWeight: FontWeight.w900,
                        fontSize: 12,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 150),
                    child: Text(
                      widget.vaultName,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  const SizedBox(width: 4),
                  const Icon(Icons.keyboard_arrow_down_rounded, color: Colors.white54, size: 16),
                ],
              ),
            ),
            actions: [
              // Sleek Merchant POS corner pill
              Padding(
                padding: const EdgeInsets.only(right: 6),
                child: InkWell(
                  onTap: _openMerchantPos,
                  borderRadius: BorderRadius.circular(20),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                    decoration: BoxDecoration(
                      color: const Color(0xFF13151C),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.07)),
                    ),
                    child: const Row(
                      children: [
                        Icon(Icons.storefront_rounded, color: Color(0xFF00D68F), size: 15),
                        SizedBox(width: 5),
                        Text('POS', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w700)),
                      ],
                    ),
                  ),
                ),
              ),
              PopupMenuButton<String>(
                tooltip: 'Account',
                color: const Color(0xFF161922),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                  side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
                ),
                icon: Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: const Color(0xFF13151C),
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white.withValues(alpha: 0.07)),
                  ),
                  child: const Icon(Icons.person_outline_rounded, color: Colors.white70, size: 18),
                ),
                onSelected: (val) {
                  if (val == 'signout' || val == 'switch') {
                    widget.onSignOut();
                  }
                },
                itemBuilder: (_) => [
                  PopupMenuItem<String>(
                    enabled: false,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(widget.vaultName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
                        const SizedBox(height: 2),
                        const Text('Self-Custody Vault', style: TextStyle(color: Color(0xFF00D68F), fontSize: 11)),
                      ],
                    ),
                  ),
                  const PopupMenuDivider(),
                  const PopupMenuItem<String>(
                    value: 'switch',
                    child: Row(
                      children: [
                        Icon(Icons.switch_account_rounded, color: Colors.white70, size: 18),
                        SizedBox(width: 10),
                        Text('Switch / Create Vault', style: TextStyle(color: Colors.white, fontSize: 13)),
                      ],
                    ),
                  ),
                  const PopupMenuItem<String>(
                    value: 'signout',
                    child: Row(
                      children: [
                        Icon(Icons.logout_rounded, color: Color(0xFFFF5C5C), size: 18),
                        SizedBox(width: 10),
                        Text('Lock & Sign Out', style: TextStyle(color: Color(0xFFFF5C5C), fontSize: 13)),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(width: 8),
            ],
          ),
          body: IndexedStack(index: _index, children: _pages),
          bottomNavigationBar: Container(
            decoration: BoxDecoration(
              color: const Color(0xFF0B0C10),
              border: Border(top: BorderSide(color: Colors.white.withValues(alpha: 0.06))),
            ),
            child: BottomNavigationBar(
              currentIndex: _index,
              onTap: (i) => setState(() => _index = i),
              backgroundColor: Colors.transparent,
              elevation: 0,
              selectedItemColor: Colors.white,
              unselectedItemColor: const Color(0xFF6B7280),
              selectedFontSize: 11,
              unselectedFontSize: 11,
              type: BottomNavigationBarType.fixed,
              items: const [
                BottomNavigationBarItem(
                  icon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.account_balance_wallet_outlined, size: 22)),
                  activeIcon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.account_balance_wallet_rounded, size: 22)),
                  label: 'Wallet',
                ),
                BottomNavigationBarItem(
                  icon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.candlestick_chart_outlined, size: 22)),
                  activeIcon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.candlestick_chart_rounded, size: 22)),
                  label: 'Markets',
                ),
                BottomNavigationBarItem(
                  icon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.rocket_launch_outlined, size: 22)),
                  activeIcon: Padding(padding: EdgeInsets.only(bottom: 3), child: Icon(Icons.rocket_launch_rounded, size: 22)),
                  label: 'Launchpad',
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}