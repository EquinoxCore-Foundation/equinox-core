import 'dart:convert';
import 'dart:typed_data';
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:crypto/crypto.dart';
import 'package:ed25519_hd_key/ed25519_hd_key.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:web3dart/web3dart.dart';

class MultiChainAddresses {
  final String evmAddress;
  final String solanaAddress;
  final String eqxAddress;

  const MultiChainAddresses({
    required this.evmAddress,
    required this.solanaAddress,
    required this.eqxAddress,
  });
}

class ChainBalance {
  final String chainName;
  final String symbol;
  final String address;
  final String balance;
  final String status;

  const ChainBalance({
    required this.chainName,
    required this.symbol,
    required this.address,
    required this.balance,
    required this.status,
  });
}

class EqxMultiChainVault {
  static const _storageKeySeed = 'eqx_sovereign_bip39_seed_v1';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static String generateNewMnemonic() => bip39.generateMnemonic();

  static bool isValidMnemonic(String phrase) =>
      bip39.validateMnemonic(phrase.trim().toLowerCase());

  static Future<void> saveSeedSecurely(String mnemonic) async {
    await _storage.write(key: _storageKeySeed, value: mnemonic.trim());
  }

  static Future<String?> loadSeedSecurely() async {
    return _storage.read(key: _storageKeySeed);
  }

  static Future<MultiChainAddresses> deriveAddresses(String mnemonic) async {
    final seed = bip39.mnemonicToSeed(mnemonic.trim());

    // 1. EVM (Ethereum, BNB Chain, Polygon) -> m/44'/60'/0'/0/0
    final rootEvm = bip32.BIP32.fromSeed(seed);
    final evmChild = rootEvm.derivePath("m/44'/60'/0'/0/0");
    final evmPriv = EthPrivateKey(evmChild.privateKey!);
    final evmAddr = evmPriv.address.hexEip55;

    // 2. Solana (SOL) -> m/44'/501'/0'/0'
    final solKey = await ED25519_HD_KEY.derivePath("m/44'/501'/0'/0'", seed);
    final solPub = await ED25519_HD_KEY.getPublicKey(solKey.key, false);
    final solAddr = _base58Encode(Uint8List.fromList(solPub));

    // 3. Equinox (EQX) -> m/44'/9333'/0'/0'
    final eqxKey = await ED25519_HD_KEY.derivePath("m/44'/9333'/0'/0'", seed);
    final eqxPub = await ED25519_HD_KEY.getPublicKey(eqxKey.key, false);
    final eqxHash = sha256.convert(eqxPub).bytes.sublist(0, 20);
    final eqxAddr = 'E${_base58Encode(Uint8List.fromList(eqxHash))}';

    return MultiChainAddresses(
      evmAddress: evmAddr,
      solanaAddress: solAddr,
      eqxAddress: eqxAddr,
    );
  }

  static Future<List<ChainBalance>> fetchAllBalances(
    MultiChainAddresses addrs, {
    String eqxRpcUrl = 'http://127.0.0.1:18545',
  }) async {
    final results = await Future.wait([
      _fetchEvmBalance('Ethereum', 'ETH', addrs.evmAddress, 'https://ethereum-rpc.publicnode.com'),
      _fetchEvmBalance('BNB Smart Chain', 'BNB', addrs.evmAddress, 'https://bsc-rpc.publicnode.com'),
      _fetchEvmBalance('Polygon', 'POL', addrs.evmAddress, 'https://polygon-bor-rpc.publicnode.com'),
      _fetchSolanaBalance(addrs.solanaAddress),
      _fetchEqxBalance(addrs.eqxAddress, eqxRpcUrl),
    ]);
    return results;
  }

  static Future<ChainBalance> _fetchEvmBalance(
    String name,
    String symbol,
    String address,
    String rpcUrl,
  ) async {
    try {
      final res = await http
          .post(
            Uri.parse(rpcUrl),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'method': 'eth_getBalance',
              'params': [address, 'latest'],
              'id': 1,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final hexVal = (data['result'] ?? '0x0').toString();
        final wei = BigInt.parse(hexVal.replaceFirst('0x', ''), radix: 16);
        final eth = wei / BigInt.from(10).pow(18);
        return ChainBalance(
          chainName: name,
          symbol: symbol,
          address: address,
          balance: eth.toStringAsFixed(6),
          status: 'Live RPC',
        );
      }
    } catch (_) {}
    return ChainBalance(
      chainName: name,
      symbol: symbol,
      address: address,
      balance: '0.000000',
      status: 'Offline',
    );
  }

  static Future<ChainBalance> _fetchSolanaBalance(String address) async {
    try {
      final res = await http
          .post(
            Uri.parse('https://api.mainnet-beta.solana.com'),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': 1,
              'method': 'getBalance',
              'params': [address],
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final lamports = (data['result']?['value'] ?? 0) as num;
        final sol = lamports / 1e9;
        return ChainBalance(
          chainName: 'Solana',
          symbol: 'SOL',
          address: address,
          balance: sol.toStringAsFixed(6),
          status: 'Live RPC',
        );
      }
    } catch (_) {}
    return ChainBalance(
      chainName: 'Solana',
      symbol: 'SOL',
      address: address,
      balance: '0.000000',
      status: 'Offline',
    );
  }

  static Future<ChainBalance> _fetchEqxBalance(String address, String rpcUrl) async {
    try {
      final res = await http
          .post(
            Uri.parse(rpcUrl),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': 1,
              'method': 'eqx_getBalance',
              'params': [address],
            }),
          )
          .timeout(const Duration(seconds: 4));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final bal = data['result']?['balance_eqx']?.toString() ?? '0.00000000';
        return ChainBalance(
          chainName: 'Equinox L1',
          symbol: 'EQX',
          address: address,
          balance: bal,
          status: 'Local Node',
        );
      }
    } catch (_) {}
    return ChainBalance(
      chainName: 'Equinox L1',
      symbol: 'EQX',
      address: address,
      balance: '0.00000000',
      status: 'Node Standby',
    );
  }

  static String _base58Encode(Uint8List bytes) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    BigInt intData = BigInt.zero;
    for (final b in bytes) {
      intData = (intData << 8) | BigInt.from(b);
    }
    final sb = StringBuffer();
    final base = BigInt.from(58);
    while (intData > BigInt.zero) {
      final rem = (intData % base).toInt();
      intData = intData ~/ base;
      sb.write(alphabet[rem]);
    }
    for (final b in bytes) {
      if (b == 0) {
        sb.write(alphabet[0]);
      } else {
        break;
      }
    }
    return sb.toString().split('').reversed.join();
  }
}