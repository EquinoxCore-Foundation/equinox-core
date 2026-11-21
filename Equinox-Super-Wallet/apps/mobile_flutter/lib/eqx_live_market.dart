import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class CandlePoint {
  final double open;
  final double high;
  final double low;
  final double close;

  const CandlePoint({
    required this.open,
    required this.high,
    required this.low,
    required this.close,
  });
}

class LiveTicker {
  final String symbol;
  final String pair;
  final double price;
  final double changePct;
  final String source;

  const LiveTicker({
    required this.symbol,
    required this.pair,
    required this.price,
    required this.changePct,
    required this.source,
  });
}

class EqxLiveMarketTab extends StatefulWidget {
  const EqxLiveMarketTab({super.key});

  @override
  State<EqxLiveMarketTab> createState() => _EqxLiveMarketTabState();
}

class _EqxLiveMarketTabState extends State<EqxLiveMarketTab> {
  static const List<String> _symbols = ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'BNBUSDT'];
  static const List<String> _intervals = ['1m', '15m', '1h', '1d'];

  String _selectedSymbol = 'BTCUSDT';
  String _selectedInterval = '15m';
  List<LiveTicker> _tickers = [];
  List<CandlePoint> _candles = [];
  String _sourceLabel = 'Connecting to Binance / Coinbase...';
  bool _loading = true;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _refreshAll();
    _timer = Timer.periodic(const Duration(seconds: 6), (_) => _refreshAll());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refreshAll() async {
    await Future.wait([_fetchTickers(), _fetchCandles()]);
  }

  Future<void> _fetchTickers() async {
    try {
      final uri = Uri.parse(
        'https://api.binance.com/api/v3/ticker/24hr?symbols=["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT"]',
      );
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final List<dynamic> data = jsonDecode(res.body) as List<dynamic>;
        final parsed = data.map((item) {
          final m = item as Map<String, dynamic>;
          final sym = m['symbol'].toString();
          return LiveTicker(
            symbol: sym.replaceAll('USDT', ''),
            pair: sym,
            price: double.tryParse(m['lastPrice'].toString()) ?? 0,
            changePct: double.tryParse(m['priceChangePercent'].toString()) ?? 0,
            source: 'Binance Live',
          );
        }).toList();
        if (mounted) {
          setState(() {
            _tickers = parsed;
            _sourceLabel = 'Live Feed: Binance Public API';
            _loading = false;
          });
        }
        return;
      }
    } catch (_) {}

    // Fallback to Coinbase Free Public Spot API
    try {
      final List<LiveTicker> cbList = [];
      for (final coin in ['BTC', 'ETH', 'SOL']) {
        final r = await http
            .get(Uri.parse('https://api.coinbase.com/v2/prices/$coin-USD/spot'))
            .timeout(const Duration(seconds: 4));
        if (r.statusCode == 200) {
          final j = jsonDecode(r.body) as Map<String, dynamic>;
          final amt = double.tryParse(j['data']['amount'].toString()) ?? 0;
          cbList.add(LiveTicker(
            symbol: coin,
            pair: '${coin}USDT',
            price: amt,
            changePct: 0.0,
            source: 'Coinbase Live',
          ));
        }
      }
      if (mounted && cbList.isNotEmpty) {
        setState(() {
          _tickers = cbList;
          _sourceLabel = 'Live Feed: Coinbase Public API';
          _loading = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _sourceLabel = 'Offline — Check Internet Connection';
          _loading = false;
        });
      }
    }
  }

  Future<void> _fetchCandles() async {
    try {
      final uri = Uri.parse(
        'https://api.binance.com/api/v3/klines?symbol=$_selectedSymbol&interval=$_selectedInterval&limit=42',
      );
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final List<dynamic> rows = jsonDecode(res.body) as List<dynamic>;
        final pts = rows.map((row) {
          final r = row as List<dynamic>;
          return CandlePoint(
            open: double.tryParse(r[1].toString()) ?? 0,
            high: double.tryParse(r[2].toString()) ?? 0,
            low: double.tryParse(r[3].toString()) ?? 0,
            close: double.tryParse(r[4].toString()) ?? 0,
          );
        }).toList();
        if (mounted) {
          setState(() => _candles = pts);
        }
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final activeTicker = _tickers.where((t) => t.pair == _selectedSymbol).isNotEmpty
        ? _tickers.firstWhere((t) => t.pair == _selectedSymbol)
        : null;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text(
              'Live Markets & Chart',
              style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: const Color(0xFF00E5A0).withValues(alpha: 0.14),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: const Color(0xFF00E5A0).withValues(alpha: 0.4)),
              ),
              child: Text(
                _sourceLabel,
                style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 10, fontWeight: FontWeight.w600),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0xFF0E1525),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(color: const Color(0xFF1E293B)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  DropdownButton<String>(
                    value: _selectedSymbol,
                    dropdownColor: const Color(0xFF111827),
                    underline: const SizedBox.shrink(),
                    style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
                    items: _symbols
                        .map((s) => DropdownMenuItem(value: s, child: Text(s.replaceAll('USDT', '/USDT'))))
                        .toList(),
                    onChanged: (val) {
                      if (val == null) return;
                      setState(() => _selectedSymbol = val);
                      _fetchCandles();
                    },
                  ),
                  if (activeTicker != null)
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Text(
                          '\$${activeTicker.price.toStringAsFixed(2)}',
                          style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          '${activeTicker.changePct >= 0 ? '+' : ''}${activeTicker.changePct.toStringAsFixed(2)}%',
                          style: TextStyle(
                            color: activeTicker.changePct >= 0 ? const Color(0xFF00E5A0) : Colors.redAccent,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: _intervals.map((tf) {
                  final sel = tf == _selectedInterval;
                  return Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: ChoiceChip(
                      label: Text(tf, style: TextStyle(color: sel ? Colors.black : Colors.white70, fontSize: 11)),
                      selected: sel,
                      selectedColor: const Color(0xFF00E5A0),
                      backgroundColor: const Color(0xFF161F33),
                      onSelected: (_) {
                        setState(() => _selectedInterval = tf);
                        _fetchCandles();
                      },
                    ),
                  );
                }).toList(),
              ),
              const SizedBox(height: 12),
              SizedBox(
                height: 210,
                width: double.infinity,
                child: _candles.isEmpty
                    ? const Center(child: CircularProgressIndicator(color: Color(0xFF00E5A0)))
                    : CustomPaint(painter: _CandlestickPainter(_candles)),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        if (_loading)
          const Center(child: Padding(padding: EdgeInsets.all(20), child: CircularProgressIndicator()))
        else
          ..._tickers.map((t) {
            final up = t.changePct >= 0;
            return InkWell(
              onTap: () {
                setState(() => _selectedSymbol = t.pair);
                _fetchCandles();
              },
              child: Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 13),
                decoration: BoxDecoration(
                  color: const Color(0xFF0E1525),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: _selectedSymbol == t.pair ? const Color(0xFF00E5A0) : const Color(0xFF1E293B),
                  ),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        CircleAvatar(
                          radius: 18,
                          backgroundColor: const Color(0xFF1E293B),
                          child: Text(t.symbol, style: const TextStyle(color: Colors.amber, fontSize: 10, fontWeight: FontWeight.bold)),
                        ),
                        const SizedBox(width: 12),
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('${t.symbol}/USDT', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                            Text(t.source, style: const TextStyle(color: Colors.white38, fontSize: 11)),
                          ],
                        ),
                      ],
                    ),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Text('\$${t.price.toStringAsFixed(2)}', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                        Text(
                          '${up ? '+' : ''}${t.changePct.toStringAsFixed(2)}%',
                          style: TextStyle(color: up ? const Color(0xFF00E5A0) : Colors.redAccent, fontSize: 12),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            );
          }),
      ],
    );
  }
}

class _CandlestickPainter extends CustomPainter {
  final List<CandlePoint> candles;
  _CandlestickPainter(this.candles);

  @override
  void paint(Canvas canvas, Size size) {
    if (candles.isEmpty) return;
    double minP = candles.map((c) => c.low).reduce(min);
    double maxP = candles.map((c) => c.high).reduce(max);
    final range = (maxP - minP).abs() < 1e-6 ? 1.0 : (maxP - minP);

    final gridPaint = Paint()
      ..color = const Color(0xFF1E293B)
      ..strokeWidth = 0.8;
    for (int i = 1; i <= 3; i++) {
      final y = size.height * i / 4;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }

    final step = size.width / candles.length;
    final bodyW = (step * 0.62).clamp(2.5, 10.0);

    double yOf(double price) => size.height - ((price - minP) / range) * (size.height - 12) - 6;

    for (int i = 0; i < candles.length; i++) {
      final c = candles[i];
      final x = i * step + step / 2;
      final bullish = c.close >= c.open;
      final color = bullish ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);

      final wickPaint = Paint()
        ..color = color
        ..strokeWidth = 1.3;
      canvas.drawLine(Offset(x, yOf(c.high)), Offset(x, yOf(c.low)), wickPaint);

      final top = yOf(max(c.open, c.close));
      final bottom = yOf(min(c.open, c.close));
      final rect = Rect.fromLTRB(x - bodyW / 2, top, x + bodyW / 2, max(bottom, top + 1.5));
      canvas.drawRect(rect, Paint()..color = color);
    }
  }

  @override
  bool shouldRepaint(covariant _CandlestickPainter oldDelegate) => oldDelegate.candles != candles;
}