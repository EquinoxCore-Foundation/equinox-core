import 'dart:convert';
import 'dart:io';

typedef JsonMap = Map<String, dynamic>;

class EquinoxRpcService {
  static const String rpcUrl = 'http://127.0.0.1:8545';
  static const int expectedChainId = 9333;

  Future<JsonMap> _call(String method, Object params) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    try {
      final request = await client.postUrl(Uri.parse(rpcUrl));
      request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      final payload = jsonEncode({
        'jsonrpc': '2.0',
        'id': DateTime.now().millisecondsSinceEpoch,
        'method': method,
        'params': params,
      });
      request.write(payload);
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      final decoded = jsonDecode(body);
      if (decoded is Map) {
        return Map<String, dynamic>.from(decoded);
      }
      return <String, dynamic>{'error': 'Invalid JSON-RPC response'};
    } finally {
      client.close(force: true);
    }
  }

  Future<bool> isNodeOnline() async {
    try {
      final res = await _call('eqx_listTokens', <String, dynamic>{});
      return res['ok'] == true || res['result'] != null;
    } catch (_) {
      return false;
    }
  }

  Future<List<JsonMap>> listTokens() async {
    final res = await _call('eqx_listTokens', <String, dynamic>{});
    final data = res['result'] ?? res;
    if (data is Map && data['tokens'] is List) {
      final rawList = data['tokens'] as List;
      return rawList
          .whereType()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    }
    return <JsonMap>[];
  }

  Future<JsonMap> deployToken({
    required String creator,
    required String name,
    required String ticker,
    required int decimals,
    required String totalSupply,
    int nonce = 1,
  }) async {
    final res = await _call('eqx_deployToken', <String, dynamic>{
      'creator': creator,
      'name': name,
      'ticker': ticker,
      'decimals': decimals,
      'total_supply': totalSupply,
      'nonce': nonce,
    });
    final data = res['result'] ?? res;
    if (data is Map) {
      return Map<String, dynamic>.from(data);
    }
    return <String, dynamic>{'ok': false, 'error': 'Unexpected RPC response'};
  }
}