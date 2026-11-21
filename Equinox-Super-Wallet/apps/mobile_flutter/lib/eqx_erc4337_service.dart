import 'dart:convert';
import 'dart:typed_data';
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';
import 'eqx_multichain_vault.dart';

class BaseSepoliaState {
  final String ownerAddress;
  final String usdcBalance;
  final String ethBalance;

  const BaseSepoliaState({
    required this.ownerAddress,
    required this.usdcBalance,
    required this.ethBalance,
  });
}

class UserOpResult {
  final bool submitted;
  final String userOpHash;
  final String message;

  const UserOpResult({
    required this.submitted,
    required this.userOpHash,
    required this.message,
  });
}

class EqxErc4337Service {
  static const int chainId = 84532; // Base Sepolia
  static const String baseSepoliaRpc = 'https://sepolia.base.org';
  static const String entryPointV07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
  static const String usdcContract = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

  static const _paymasterKey = 'eqx_base_sepolia_paymaster_url_v1';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Future<void> savePaymasterUrl(String url) async {
    await _storage.write(key: _paymasterKey, value: url.trim());
  }

  static Future<String> loadPaymasterUrl() async {
    return (await _storage.read(key: _paymasterKey)) ?? '';
  }

  static Future<EthPrivateKey> _loadOwnerKey() async {
    String? seed = await EqxMultiChainVault.loadSeedSecurely();
    if (seed == null || !EqxMultiChainVault.isValidMnemonic(seed)) {
      seed = EqxMultiChainVault.generateNewMnemonic();
      await EqxMultiChainVault.saveSeedSecurely(seed);
    }
    final seedBytes = bip39.mnemonicToSeed(seed.trim());
    final root = bip32.BIP32.fromSeed(seedBytes);
    final child = root.derivePath("m/44'/60'/0'/0/0");
    return EthPrivateKey(child.privateKey!);
  }

  static Future<BaseSepoliaState> fetchBaseSepoliaState() async {
    final key = await _loadOwnerKey();
    final owner = key.address.hexEip55;

    final results = await Future.wait([
      _fetchUsdcBalance(owner),
      _fetchEthBalance(owner),
    ]);

    return BaseSepoliaState(
      ownerAddress: owner,
      usdcBalance: results[0],
      ethBalance: results[1],
    );
  }

  static Future<String> _fetchUsdcBalance(String address) async {
    try {
      final cleanAddr = address.toLowerCase().replaceFirst('0x', '').padLeft(64, '0');
      final data = '0x70a08231$cleanAddr'; // balanceOf(address)
      final res = await http
          .post(
            Uri.parse(baseSepoliaRpc),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': 1,
              'method': 'eth_call',
              'params': [
                {'to': usdcContract, 'data': data},
                'latest',
              ],
            }),
          )
          .timeout(const Duration(seconds: 6));
      if (res.statusCode == 200) {
        final body = jsonDecode(res.body) as Map<String, dynamic>;
        final hexStr = (body['result'] ?? '0x0').toString().replaceFirst('0x', '');
        final raw = hexStr.isEmpty ? BigInt.zero : BigInt.parse(hexStr, radix: 16);
        final whole = raw ~/ BigInt.from(1000000);
        final frac = (raw % BigInt.from(1000000)).toString().padLeft(6, '0');
        return '$whole.${frac.substring(0, 4)}';
      }
    } catch (_) {}
    return '0.0000';
  }

  static Future<String> _fetchEthBalance(String address) async {
    try {
      final res = await http
          .post(
            Uri.parse(baseSepoliaRpc),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'jsonrpc': '2.0',
              'id': 1,
              'method': 'eth_getBalance',
              'params': [address, 'latest'],
            }),
          )
          .timeout(const Duration(seconds: 6));
      if (res.statusCode == 200) {
        final body = jsonDecode(res.body) as Map<String, dynamic>;
        final hexVal = (body['result'] ?? '0x0').toString().replaceFirst('0x', '');
        final wei = hexVal.isEmpty ? BigInt.zero : BigInt.parse(hexVal, radix: 16);
        final eth = wei / BigInt.from(10).pow(18);
        return eth.toStringAsFixed(5);
      }
    } catch (_) {}
    return '0.00000';
  }

  /// Encodes ERC-20 transfer(address,uint256) strictly using BigInt (6 decimals for USDC)
  static String encodeUsdcTransferCalldata(String recipientHex, BigInt amountMicroUsdc) {
    final cleanTo = recipientHex.trim().toLowerCase().replaceFirst('0x', '').padLeft(64, '0');
    final amtHex = amountMicroUsdc.toRadixString(16).padLeft(64, '0');
    return '0xa9059cbb$cleanTo$amtHex';
  }

  static BigInt parseUsdcToMicro(String amountText) {
    final clean = amountText.trim();
    if (clean.isEmpty) return BigInt.zero;
    final parts = clean.split('.');
    final whole = BigInt.tryParse(parts[0].isEmpty ? '0' : parts[0]) ?? BigInt.zero;
    final fracStr = parts.length > 1 ? parts[1].padRight(6, '0').substring(0, 6) : '000000';
    final frac = BigInt.tryParse(fracStr) ?? BigInt.zero;
    return whole * BigInt.from(1000000) + frac;
  }

  static Future<UserOpResult> sendGaslessUsdc({
    required String recipient,
    required String amountUsdc,
    required String bundlerPaymasterUrl,
  }) async {
    final rec = recipient.trim();
    if (!RegExp(r'^0x[a-fA-F0-9]{40}$').hasMatch(rec)) {
      throw Exception('Invalid EVM recipient address (must be 0x + 40 hex chars)');
    }
    final microAmt = parseUsdcToMicro(amountUsdc);
    if (microAmt <= BigInt.zero) {
      throw Exception('Amount must be greater than 0 USDC');
    }

    final ownerKey = await _loadOwnerKey();
    final sender = ownerKey.address.hexEip55;
    final callData = encodeUsdcTransferCalldata(rec, microAmt);

    // Build ERC-4337 v0.7 UserOperation payload
    final userOp = <String, dynamic>{
      'sender': sender,
      'nonce': '0x0',
      'callData': callData,
      'callGasLimit': '0x186a0',
      'verificationGasLimit': '0x30d40',
      'preVerificationGas': '0xc350',
      'maxFeePerGas': '0x59682f00',
      'maxPriorityFeePerGas': '0x3b9aca00',
      'signature': '0x',
    };

    // Sign locally on-device (Private Key NEVER leaves device)
    final digest = keccak256(Uint8List.fromList(utf8.encode(jsonEncode({
      'chainId': chainId,
      'entryPoint': entryPointV07,
      'sender': sender,
      'to': usdcContract,
      'callData': callData,
    }))));
    final sigBytes = ownerKey.signPersonalMessageToUint8List(digest);
    final localSigHex = bytesToHex(sigBytes, include0x: true);
    userOp['signature'] = localSigHex;

    final rpc = bundlerPaymasterUrl.trim();
    if (rpc.isEmpty) {
      return UserOpResult(
        submitted: false,
        userOpHash: bytesToHex(digest, include0x: true),
        message: 'Locally signed ERC-4337 UserOp ready! Add a free Pimlico/CDP Base Sepolia Paymaster URL to broadcast gasless on-chain.',
      );
    }

    // 1. Request Paymaster Gas Sponsorship (pm_sponsorUserOperation)
    final sponsorRes = await http
        .post(
          Uri.parse(rpc),
          headers: const {'Content-Type': 'application/json'},
          body: jsonEncode({
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'pm_sponsorUserOperation',
            'params': [userOp, entryPointV07],
          }),
        )
        .timeout(const Duration(seconds: 10));

    if (sponsorRes.statusCode != 200) {
      throw Exception('Paymaster HTTP ${sponsorRes.statusCode}');
    }
    final sponsorJson = jsonDecode(sponsorRes.body) as Map<String, dynamic>;
    if (sponsorJson['error'] != null) {
      throw Exception('Paymaster Error: ${sponsorJson['error']['message'] ?? sponsorJson['error']}');
    }

    final sponsored = sponsorJson['result'] as Map<String, dynamic>?;
    if (sponsored != null) {
      userOp.addAll(sponsored);
    }

    // 2. Submit Sponsored UserOp to Bundler (eth_sendUserOperation)
    final sendRes = await http
        .post(
          Uri.parse(rpc),
          headers: const {'Content-Type': 'application/json'},
          body: jsonEncode({
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'eth_sendUserOperation',
            'params': [userOp, entryPointV07],
          }),
        )
        .timeout(const Duration(seconds: 10));

    final sendJson = jsonDecode(sendRes.body) as Map<String, dynamic>;
    if (sendJson['error'] != null) {
      throw Exception('Bundler Error: ${sendJson['error']['message'] ?? sendJson['error']}');
    }
    final opHash = sendJson['result'].toString();
    return UserOpResult(
      submitted: true,
      userOpHash: opHash,
      message: 'Gasless UserOperation submitted to Base Sepolia Bundler!',
    );
  }
}