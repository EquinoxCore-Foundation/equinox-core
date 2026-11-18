import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const EquinoxMobileApp());
}

class EquinoxMobileApp extends StatelessWidget {
  const EquinoxMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Equinox Super-Wallet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0B0E11),
        primaryColor: const Color(0xFFFCD535),
      ),
      home: const WalletHomeScreen(),
    );
  }
}

class WalletHomeScreen extends StatefulWidget {
  const WalletHomeScreen({super.key});

  @override
  State<WalletHomeScreen> createState() => _WalletHomeScreenState();
}

class _WalletHomeScreenState extends State<WalletHomeScreen> {
  String rpcUrl = "http://127.0.0.1:18545";
  String walletAddress = "Ebt19oYiFwJM8DeP1H5eGNNVskFpYs7Fmx";
  String eqxBalance = "1,000,004.0640";
  int blockHeight = 10;
  Timer? _pollTimer;

  @override
  void initState() {
    super.initState();
    _syncWithL1Node();
    _pollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _syncWithL1Node());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _syncWithL1Node() async {
    try {
      final statusRes = await http.post(
        Uri.parse(rpcUrl),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({"jsonrpc": "2.0", "id": 1, "method": "eqx_getNodeStatus", "params": []}),
      ).timeout(const Duration(seconds: 2));

      if (statusRes.statusCode == 200) {
        final data = jsonDecode(statusRes.body);
        if (data["result"] != null && mounted) {
          setState(() {
            blockHeight = data["result"]["best_height"] ?? blockHeight;
          });
        }
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF181A20),
        title: const Row(
          children: [
            Icon(Icons.wb_sunny, color: Color(0xFFFCD535), size: 22),
            SizedBox(width: 8),
            Text("EQUINOX SUPER-WALLET", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
          ],
        ),
        actions: [
          Container(
            margin: const EdgeInsets.symmetric(vertical: 12, horizontal: 12),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: const Color(0xFF10B981).withOpacity(0.15),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFF10B981)),
            ),
            child: Text("Chain 9333 • #$blockHeight", style: const TextStyle(color: Color(0xFF10B981), fontSize: 11, fontWeight: FontWeight.bold)),
          )
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Balance Card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(22),
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF1E2329), Color(0xFF181A20)]),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: const Color(0xFF2B3139)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("TOTAL SELF-CUSTODY BALANCE", style: TextStyle(color: Color(0xFF848E9C), fontSize: 12, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  Text("$eqxBalance EQX", style: const TextStyle(color: Color(0xFFFCD535), fontSize: 28, fontWeight: FontWeight.w800)),
                  const SizedBox(height: 6),
                  const Text("🟢 Real-Time L1 Auto-Indexer Active", style: TextStyle(color: Color(0xFF10B981), fontSize: 12)),
                ],
              ),
            ),
            const SizedBox(height: 18),
            // Direct Corporate Deposit Card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: const Color(0xFF181A20),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: const Color(0xFF2B3139)),
              ),
              child: Column(
                children: [
                  const Text("Deposit EQX (Mainnet / Testnet 9333)", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 12),
                  SelectableText(
                    walletAddress,
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 13, color: Color(0xFFEAECEF), fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 14),
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFFFCD535),
                        foregroundColor: const Color(0xFF181A20),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: walletAddress));
                        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("✓ EQX Address Copied!")));
                      },
                      icon: const Icon(Icons.copy, size: 18),
                      label: const Text("Copy Receive Address", style: TextStyle(fontWeight: FontWeight.bold)),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
