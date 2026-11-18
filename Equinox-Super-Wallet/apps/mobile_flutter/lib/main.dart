import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const EquinoxSuperWalletApp());
}

class EquinoxSuperWalletApp extends StatelessWidget {
  const EquinoxSuperWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Equinox Super-Wallet (EQX)',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0B0E14),
        primaryColor: const Color(0xFFFCD535),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFFFCD535),
          secondary: Color(0xFF0ECB81),
          surface: Color(0xFF161A25),
        ),
      ),
      home: const EquinoxHomeScreen(),
    );
  }
}

class EquinoxHomeScreen extends StatefulWidget {
  const EquinoxHomeScreen({super.key});

  @override
  State<EquinoxHomeScreen> createState() => _EquinoxHomeScreenState();
}

class _EquinoxHomeScreenState extends State<EquinoxHomeScreen> {
  int _tabIndex = 0;
  final String walletAddress = "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx";
  final String rpcEndpoint = "http://127.0.0.1:18545 (Chain ID: 9333)";

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF161A25),
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: const Color(0xFFFCD535),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Text("EQX", style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 13)),
            ),
            const SizedBox(width: 10),
            const Text("Equinox Super-Wallet", style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
          ],
        ),
      ),
      body: IndexedStack(
        index: _tabIndex,
        children: [
          _buildVaultTab(context),
          _buildDexTab(),
          _buildMerchantPosTab(context),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        backgroundColor: const Color(0xFF161A25),
        selectedItemColor: const Color(0xFFFCD535),
        unselectedItemColor: Colors.white54,
        currentIndex: _tabIndex,
        onTap: (idx) => setState(() => _tabIndex = idx),
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.account_balance_wallet), label: "Vault & Node"),
          BottomNavigationBarItem(icon: Icon(Icons.swap_horiz), label: "AMM DEX"),
          BottomNavigationBarItem(icon: Icon(Icons.qr_code_scanner), label: "Merchant POS"),
        ],
      ),
    );
  }

  Widget _buildVaultTab(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            gradient: const LinearGradient(colors: [Color(0xFF1E2329), Color(0xFF141820)]),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: const Color(0xFFFCD535).withOpacity(0.35)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text("SOVEREIGN L1 UTXO BALANCE (CHAIN 9333)", style: TextStyle(color: Colors.white60, fontSize: 11, letterSpacing: 1.1)),
              const SizedBox(height: 8),
              const Text("0.00000000 EQX", style: TextStyle(color: Color(0xFFFCD535), fontSize: 28, fontWeight: FontWeight.bold)),
              const SizedBox(height: 6),
              Text(rpcEndpoint, style: const TextStyle(color: Color(0xFF0ECB81), fontSize: 12)),
              const Divider(height: 24, color: Colors.white12),
              const Text("Your Receiving Address (Base58Check):", style: TextStyle(color: Colors.white70, fontSize: 12)),
              const SizedBox(height: 6),
              SelectableText(walletAddress, style: const TextStyle(fontFamily: 'monospace', fontSize: 13, color: Color(0xFFEAECEF), fontWeight: FontWeight.bold)),
              const SizedBox(height: 14),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFFCD535),
                    foregroundColor: const Color(0xFF181A20),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: walletAddress));
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("EQX Address Copied!")));
                  },
                  icon: const Icon(Icons.copy, size: 18),
                  label: const Text("Copy Receive Address", style: TextStyle(fontWeight: FontWeight.bold)),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildDexTab() {
    return const Center(
      child: Padding(
        padding: EdgeInsets.all(24),
        child: Text(
          "On-Chain Constant-Product AMM DEX (0.30% LP Fee Sharing)\nConnected to src/dex.rs & src/dividend.rs",
          textAlign: TextAlign.center,
          style: TextStyle(color: Colors.white70, fontSize: 15),
        ),
      ),
    );
  }

  Widget _buildMerchantPosTab(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.qr_code_2, size: 140, color: Color(0xFFFCD535)),
            const SizedBox(height: 12),
            const Text("Zero-Fee Instant Merchant POS", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Text("equinox:$walletAddress?chain=9333", textAlign: TextAlign.center, style: const TextStyle(color: Colors.white60, fontSize: 12)),
          ],
        ),
      ),
    );
  }
}
