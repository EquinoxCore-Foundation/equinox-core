import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

class CandlePoint {
  final double open;
  final double high;
  final double low;
  final double close;
  final double volume;
  final int timeMs;

  const CandlePoint({
    required this.open,
    required this.high,
    required this.low,
    required this.close,
    required this.volume,
    required this.timeMs,
  });
}

class LiveTicker {
  final String symbol;
  final String pair;
  final double price;
  final double changePct;
  final double high24h;
  final double low24h;
  final double quoteVol;

  const LiveTicker({
    required this.symbol,
    required this.pair,
    required this.price,
    required this.changePct,
    required this.high24h,
    required this.low24h,
    required this.quoteVol,
  });
}

class MarketTrade {
  final String time;
  final bool isBuy;
  final double price;
  final double qty;
  final double valueUsd;

  const MarketTrade({
    required this.time,
    required this.isBuy,
    required this.price,
    required this.qty,
    required this.valueUsd,
  });
}

class OrderBookLevel {
  final double price;
  final double qty;

  const OrderBookLevel({required this.price, required this.qty});
}

class PerpPosition {
  final String id;
  final String symbol;
  final bool isLong;
  final double marginUsd;
  final int leverage;
  final double entryPrice;
  final double liqPrice;

  const PerpPosition({
    required this.id,
    required this.symbol,
    required this.isLong,
    required this.marginUsd,
    required this.leverage,
    required this.entryPrice,
    required this.liqPrice,
  });

  double get sizeUsd => marginUsd * leverage;
}

class TrackedWallet {
  final String label;
  final String address;

  const TrackedWallet({required this.label, required this.address});
}

class EqxLiveMarketTab extends StatefulWidget {
  const EqxLiveMarketTab({super.key});

  @override
  State<EqxLiveMarketTab> createState() => _EqxLiveMarketTabState();
}

class _EqxLiveMarketTabState extends State<EqxLiveMarketTab> {
  static const List<String> _symbols = [
    'BTCUSDT',
    'ETHUSDT',
    'SOLUSDT',
    'BNBUSDT',
    'XRPUSDT',
    'DOGEUSDT',
    'AVAXUSDT',
    'LINKUSDT',
  ];
  static const List<String> _intervals = ['1m', '5m', '15m', '1h', '4h', '1d'];

  String _selectedSymbol = 'BTCUSDT';
  String _selectedInterval = '15m';
  int _leftTab = 1; // 0: Tokens, 1: Perps, 2: Track
  int _bottomTab = 0; // 0: Order Book, 1: Trades, 2: Positions, 3: My Trades

  List<LiveTicker> _tickers = [];
  List<CandlePoint> _candles = [];
  List<MarketTrade> _recentTrades = [];
  List<OrderBookLevel> _asks = [];
  List<OrderBookLevel> _bids = [];

  final List<MarketTrade> _myTrades = [];
  final List<PerpPosition> _perpPositions = [];
  final List<TrackedWallet> _trackedWallets = [
    const TrackedWallet(label: 'Base Whale #1', address: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'),
  ];

  bool _loading = true;
  bool _paperMode = true;
  bool _isPerpsMode = true;
  bool _isLongOrBuy = true;
  bool _autoClose = false;
  bool _showFeeDetails = false;
  int _leverage = 20;
  double _paperUsdt = 10000.0;
  String _feedStatus = 'Connecting...';
  Timer? _timer;

  final TextEditingController _amountCtrl = TextEditingController(text: '250');

  @override
  void initState() {
    super.initState();
    _refreshAll();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => _refreshAll());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _amountCtrl.dispose();
    super.dispose();
  }

  String get _baseCoin => _selectedSymbol.replaceAll('USDT', '');

  LiveTicker? get _activeTicker {
    for (final t in _tickers) {
      if (t.pair == _selectedSymbol) return t;
    }
    return null;
  }

  Future<void> _refreshAll() async {
    await Future.wait([
      _fetchTickers(),
      _fetchCandles(),
      _fetchRecentTrades(),
      _fetchOrderBook(),
    ]);
  }

  Future<void> _fetchTickers() async {
    try {
      final syms = jsonEncode(_symbols);
      final uri = Uri.parse('https://api.binance.com/api/v3/ticker/24hr?symbols=$syms');
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final List<dynamic> data = jsonDecode(res.body) as List<dynamic>;
        final parsed = data.map((item) {
          final m = item as Map<String, dynamic>;
          final pair = m['symbol'].toString();
          return LiveTicker(
            symbol: pair.replaceAll('USDT', ''),
            pair: pair,
            price: double.tryParse(m['lastPrice'].toString()) ?? 0,
            changePct: double.tryParse(m['priceChangePercent'].toString()) ?? 0,
            high24h: double.tryParse(m['highPrice'].toString()) ?? 0,
            low24h: double.tryParse(m['lowPrice'].toString()) ?? 0,
            quoteVol: double.tryParse(m['quoteVolume'].toString()) ?? 0,
          );
        }).toList();
        if (mounted) {
          setState(() {
            _tickers = parsed;
            _feedStatus = 'Live Feed';
            _loading = false;
          });
        }
        return;
      }
    } catch (_) {}
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _fetchCandles() async {
    try {
      final uri = Uri.parse(
        'https://api.binance.com/api/v3/klines?symbol=$_selectedSymbol&interval=$_selectedInterval&limit=64',
      );
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final List<dynamic> rows = jsonDecode(res.body) as List<dynamic>;
        final pts = rows.map((row) {
          final r = row as List<dynamic>;
          return CandlePoint(
            timeMs: (r[0] as num).toInt(),
            open: double.tryParse(r[1].toString()) ?? 0,
            high: double.tryParse(r[2].toString()) ?? 0,
            low: double.tryParse(r[3].toString()) ?? 0,
            close: double.tryParse(r[4].toString()) ?? 0,
            volume: double.tryParse(r[5].toString()) ?? 0,
          );
        }).toList();
        if (mounted) setState(() => _candles = pts);
      }
    } catch (_) {}
  }

  Future<void> _fetchRecentTrades() async {
    try {
      final uri = Uri.parse('https://api.binance.com/api/v3/trades?symbol=$_selectedSymbol&limit=20');
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final List<dynamic> rows = jsonDecode(res.body) as List<dynamic>;
        final list = rows.reversed.map((row) {
          final m = row as Map<String, dynamic>;
          final p = double.tryParse(m['price'].toString()) ?? 0;
          final q = double.tryParse(m['qty'].toString()) ?? 0;
          final dt = DateTime.fromMillisecondsSinceEpoch((m['time'] as num).toInt());
          final ts = '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}:${dt.second.toString().padLeft(2, '0')}';
          return MarketTrade(
            time: ts,
            isBuy: !(m['isBuyerMaker'] == true),
            price: p,
            qty: q,
            valueUsd: p * q,
          );
        }).toList();
        if (mounted) setState(() => _recentTrades = list);
      }
    } catch (_) {}
  }

  Future<void> _fetchOrderBook() async {
    try {
      final uri = Uri.parse('https://api.binance.com/api/v3/depth?symbol=$_selectedSymbol&limit=10');
      final res = await http.get(uri).timeout(const Duration(seconds: 5));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final rawAsks = (data['asks'] as List<dynamic>).take(8).toList().reversed;
        final rawBids = (data['bids'] as List<dynamic>).take(8);
        final asks = rawAsks
            .map((e) => OrderBookLevel(
                  price: double.tryParse(e[0].toString()) ?? 0,
                  qty: double.tryParse(e[1].toString()) ?? 0,
                ))
            .toList();
        final bids = rawBids
            .map((e) => OrderBookLevel(
                  price: double.tryParse(e[0].toString()) ?? 0,
                  qty: double.tryParse(e[1].toString()) ?? 0,
                ))
            .toList();
        if (mounted) {
          setState(() {
            _asks = asks;
            _bids = bids;
          });
        }
      }
    } catch (_) {}
  }

  double _calcLiqPrice(double entry, int lev, bool isLong) {
    if (entry <= 0 || lev <= 0) return 0;
    final factor = 0.9 / lev;
    return isLong ? entry * (1 - factor) : entry * (1 + factor);
  }

  void _executeOrder() {
    final t = _activeTicker;
    if (t == null || t.price <= 0) return;
    final margin = double.tryParse(_amountCtrl.text.trim()) ?? 0;
    if (margin <= 0) return;

    if (!_paperMode) {
      _toast('Live Perps/Spot ready for Hyperliquid & ERC-4337 Router. Enable Paper Mode to practice.', err: false);
      return;
    }

    if (margin > _paperUsdt) {
      _toast('Insufficient Paper USDT balance', err: true);
      return;
    }

    final now = DateTime.now();
    final ts = '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}:${now.second.toString().padLeft(2, '0')}';
    HapticFeedback.mediumImpact();

    if (_isPerpsMode) {
      final liq = _calcLiqPrice(t.price, _leverage, _isLongOrBuy);
      final pos = PerpPosition(
        id: '${now.millisecondsSinceEpoch}',
        symbol: _baseCoin,
        isLong: _isLongOrBuy,
        marginUsd: margin,
        leverage: _leverage,
        entryPrice: t.price,
        liqPrice: liq,
      );
      setState(() {
        _paperUsdt -= margin;
        _perpPositions.insert(0, pos);
        _myTrades.insert(
          0,
          MarketTrade(
            time: ts,
            isBuy: _isLongOrBuy,
            price: t.price,
            qty: pos.sizeUsd / t.price,
            valueUsd: pos.sizeUsd,
          ),
        );
        _bottomTab = 2;
      });
      _toast('${_isLongOrBuy ? "Long" : "Short"} ${_leverage}x $_baseCoin opened @ \$${t.price.toStringAsFixed(2)}');
    } else {
      final qty = (margin * 0.999) / t.price;
      setState(() {
        _paperUsdt -= margin;
        _myTrades.insert(0, MarketTrade(time: ts, isBuy: _isLongOrBuy, price: t.price, qty: qty, valueUsd: margin));
        _bottomTab = 3;
      });
      _toast('Paper ${_isLongOrBuy ? "Buy" : "Sell"} ${qty.toStringAsFixed(4)} $_baseCoin @ \$${t.price.toStringAsFixed(2)}');
    }
  }

  void _closePerpPosition(PerpPosition pos) {
    final mark = _tickers.where((t) => t.symbol == pos.symbol).firstOrNull?.price ?? pos.entryPrice;
    final priceDiff = pos.isLong ? (mark - pos.entryPrice) : (pos.entryPrice - mark);
    final pnl = (priceDiff / pos.entryPrice) * pos.sizeUsd;
    final returned = (pos.marginUsd + pnl).clamp(0.0, double.infinity);

    HapticFeedback.mediumImpact();
    setState(() {
      _perpPositions.removeWhere((p) => p.id == pos.id);
      _paperUsdt += returned;
    });
    _toast('Closed ${pos.symbol} ${pos.leverage}x • P&L: ${pnl >= 0 ? '+' : ''}\$${pnl.toStringAsFixed(2)}');
  }

  void _showAddWalletDialog() {
    final labelCtrl = TextEditingController();
    final addrCtrl = TextEditingController();
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF111827),
        title: const Text('Track Wallet Address', style: TextStyle(color: Colors.white, fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: labelCtrl,
              style: const TextStyle(color: Colors.white, fontSize: 13),
              decoration: const InputDecoration(hintText: 'Label (e.g. Smart Money #1)', hintStyle: TextStyle(color: Colors.white38)),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: addrCtrl,
              style: const TextStyle(color: Colors.white, fontSize: 13),
              decoration: const InputDecoration(hintText: '0x..., SOL or EQX Address', hintStyle: TextStyle(color: Colors.white38)),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF00E5A0), foregroundColor: Colors.black),
            onPressed: () {
              final a = addrCtrl.text.trim();
              if (a.isNotEmpty) {
                setState(() {
                  _trackedWallets.insert(
                    0,
                    TrackedWallet(
                      label: labelCtrl.text.trim().isEmpty ? 'Tracked Wallet' : labelCtrl.text.trim(),
                      address: a,
                    ),
                  );
                });
              }
              Navigator.pop(ctx);
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  void _toast(String msg, {bool err = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: err ? Colors.redAccent : const Color(0xFF059669)),
    );
  }

  String _fmtCompact(double v) {
    if (v >= 1e9) return '\$${(v / 1e9).toStringAsFixed(2)}B';
    if (v >= 1e6) return '\$${(v / 1e6).toStringAsFixed(2)}M';
    if (v >= 1e3) return '\$${(v / 1e3).toStringAsFixed(1)}K';
    return '\$${v.toStringAsFixed(2)}';
  }

  @override
  Widget build(BuildContext context) {
    final isDesktop = MediaQuery.of(context).size.width >= 1020;
    return Container(
      color: const Color(0xFF090C12),
      child: Column(
        children: [
          _buildTopStatusStrip(),
          Expanded(
            child: isDesktop ? _buildDesktopLayout() : _buildMobileLayout(),
          ),
        ],
      ),
    );
  }

  Widget _buildTopStatusStrip() {
    final t = _activeTicker;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
      decoration: const BoxDecoration(
        color: Color(0xFF0D111A),
        border: Border(bottom: BorderSide(color: Color(0xFF1C2333))),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: const Color(0xFF00E5A0).withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF00E5A0).withValues(alpha: 0.4)),
            ),
            child: Text(
              '${_isPerpsMode ? "PERPS" : "SPOT"} • $_feedStatus',
              style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 10, fontWeight: FontWeight.bold),
            ),
          ),
          const SizedBox(width: 12),
          if (t != null)
            Expanded(
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    Text('$_baseCoin-PERP', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13)),
                    const SizedBox(width: 14),
                    _statMini('Mark', '\$${t.price.toStringAsFixed(t.price < 10 ? 4 : 2)}', Colors.white),
                    _statMini('24h', '${t.changePct >= 0 ? '+' : ''}${t.changePct.toStringAsFixed(2)}%', t.changePct >= 0 ? const Color(0xFF00E5A0) : const Color(0xFFEF4444)),
                    _statMini('24h Vol', _fmtCompact(t.quoteVol), Colors.white70),
                  ],
                ),
              ),
            )
          else
            const Spacer(),
          const Text('Paper', style: TextStyle(color: Colors.white70, fontSize: 11, fontWeight: FontWeight.w600)),
          Transform.scale(
            scale: 0.78,
            child: Switch(
              value: _paperMode,
              activeThumbColor: const Color(0xFF00E5A0),
              onChanged: (v) => setState(() => _paperMode = v),
            ),
          ),
        ],
      ),
    );
  }

  Widget _statMini(String label, String val, Color color) {
    return Padding(
      padding: const EdgeInsets.only(right: 14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(color: Colors.white38, fontSize: 9)),
          Text(val, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }

  Widget _buildDesktopLayout() {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SizedBox(width: 240, child: _buildLeftPanel()),
        Expanded(
          child: Column(
            children: [
              Expanded(flex: 6, child: _buildChartPanel()),
              Expanded(flex: 4, child: _buildBottomPanel()),
            ],
          ),
        ),
        SizedBox(width: 315, child: _buildRightExecutionPanel()),
      ],
    );
  }

  Widget _buildMobileLayout() {
    return ListView(
      padding: const EdgeInsets.only(bottom: 40),
      children: [
        SizedBox(height: 290, child: _buildChartPanel()),
        _buildRightExecutionPanel(scrollable: false),
        SizedBox(height: 280, child: _buildBottomPanel()),
        SizedBox(height: 260, child: _buildLeftPanel()),
      ],
    );
  }

  Widget _buildLeftPanel() {
    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF0B0F17),
        border: Border(right: BorderSide(color: Color(0xFF1C2333))),
      ),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(10, 8, 6, 6),
            child: Row(
              children: [
                _miniTab('Tokens', _leftTab == 0, () => setState(() { _leftTab = 0; _isPerpsMode = false; })),
                _miniTab('Perps', _leftTab == 1, () => setState(() { _leftTab = 1; _isPerpsMode = true; })),
                _miniTab('Track', _leftTab == 2, () => setState(() => _leftTab = 2)),
                const Spacer(),
                if (_leftTab == 2)
                  InkWell(
                    onTap: _showAddWalletDialog,
                    child: const Padding(
                      padding: EdgeInsets.all(4),
                      child: Icon(Icons.add, color: Color(0xFF00E5A0), size: 18),
                    ),
                  ),
              ],
            ),
          ),
          const Divider(height: 1, color: Color(0xFF1C2333)),
          Expanded(
            child: _leftTab == 2 ? _buildWalletTrackerList() : _buildMarketWatchlist(),
          ),
        ],
      ),
    );
  }

  Widget _buildWalletTrackerList() {
    if (_trackedWallets.isEmpty) {
      return Center(
        child: TextButton.icon(
          onPressed: _showAddWalletDialog,
          icon: const Icon(Icons.add, color: Color(0xFF00E5A0)),
          label: const Text('Add Wallet to Track', style: TextStyle(color: Colors.white70, fontSize: 12)),
        ),
      );
    }
    return ListView.builder(
      itemCount: _trackedWallets.length,
      itemBuilder: (context, i) {
        final w = _trackedWallets[i];
        final short = w.address.length > 14
            ? '${w.address.substring(0, 6)}...${w.address.substring(w.address.length - 5)}'
            : w.address;
        return Material(
          color: Colors.transparent,
          child: ListTile(
            dense: true,
            title: Text(w.label, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
            subtitle: Text(short, style: const TextStyle(color: Colors.white54, fontSize: 10, fontFamily: 'monospace')),
            trailing: IconButton(
              icon: const Icon(Icons.close, size: 15, color: Colors.white38),
              onPressed: () => setState(() => _trackedWallets.removeAt(i)),
            ),
            onTap: () {
              Clipboard.setData(ClipboardData(text: w.address));
              _toast('Copied ${w.label} address');
            },
          ),
        );
      },
    );
  }

  Widget _buildMarketWatchlist() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: Color(0xFF00E5A0)));
    }
    return ListView.builder(
      itemCount: _tickers.length,
      itemBuilder: (context, i) {
        final t = _tickers[i];
        final sel = t.pair == _selectedSymbol;
        final up = t.changePct >= 0;
        return InkWell(
          onTap: () {
            setState(() => _selectedSymbol = t.pair);
            _refreshAll();
          },
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
            color: sel ? const Color(0xFF162033) : Colors.transparent,
            child: Row(
              children: [
                CircleAvatar(
                  radius: 13,
                  backgroundColor: const Color(0xFF1C2538),
                  child: Text(t.symbol.substring(0, min(3, t.symbol.length)), style: const TextStyle(color: Colors.amber, fontSize: 8, fontWeight: FontWeight.bold)),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Row(
                    children: [
                      Text(t.symbol, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                      if (_leftTab == 1) ...[
                        const SizedBox(width: 4),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                          decoration: BoxDecoration(color: const Color(0xFF1F2937), borderRadius: BorderRadius.circular(4)),
                          child: const Text('40x', style: TextStyle(color: Colors.white54, fontSize: 8)),
                        ),
                      ],
                    ],
                  ),
                ),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text('\$${t.price.toStringAsFixed(t.price < 10 ? 3 : 2)}', style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600)),
                    Text(
                      '${up ? '+' : ''}${t.changePct.toStringAsFixed(2)}%',
                      style: TextStyle(color: up ? const Color(0xFF00E5A0) : const Color(0xFFEF4444), fontSize: 10),
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildChartPanel() {
    final last = _candles.isNotEmpty ? _candles.last : null;
    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF090C12),
        border: Border(bottom: BorderSide(color: Color(0xFF1C2333))),
      ),
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              ..._intervals.map((tf) {
                final active = tf == _selectedInterval;
                return GestureDetector(
                  onTap: () {
                    setState(() => _selectedInterval = tf);
                    _fetchCandles();
                  },
                  child: Container(
                    margin: const EdgeInsets.only(right: 6),
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: active ? const Color(0xFF1E293B) : Colors.transparent,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(tf, style: TextStyle(color: active ? const Color(0xFF00E5A0) : Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
                  ),
                );
              }),
              const Spacer(),
              if (last != null)
                Text(
                  'O ${last.open.toStringAsFixed(2)}  H ${last.high.toStringAsFixed(2)}  L ${last.low.toStringAsFixed(2)}  C ${last.close.toStringAsFixed(2)}',
                  style: const TextStyle(color: Colors.white60, fontSize: 10, fontFamily: 'monospace'),
                ),
            ],
          ),
          const SizedBox(height: 8),
          Expanded(
            child: _candles.isEmpty
                ? const Center(child: CircularProgressIndicator(color: Color(0xFF00E5A0)))
                : CustomPaint(size: Size.infinite, painter: _PerpsChartPainter(_candles)),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomPanel() {
    return Container(
      color: const Color(0xFF0B0F17),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: [
                  _miniTab('Order Book', _bottomTab == 0, () => setState(() => _bottomTab = 0)),
                  _miniTab('Live Trades', _bottomTab == 1, () => setState(() => _bottomTab = 1)),
                  _miniTab('Positions (${_perpPositions.length})', _bottomTab == 2, () => setState(() => _bottomTab = 2)),
                  _miniTab('My Trades (${_myTrades.length})', _bottomTab == 3, () => setState(() => _bottomTab = 3)),
                ],
              ),
            ),
          ),
          const Divider(height: 1, color: Color(0xFF1C2333)),
          Expanded(
            child: _bottomTab == 0
                ? _buildOrderBookView()
                : _bottomTab == 1
                    ? _buildTradesTable(_recentTrades)
                    : _bottomTab == 2
                        ? _buildPerpPositionsView()
                        : _buildTradesTable(_myTrades),
          ),
        ],
      ),
    );
  }

  Widget _buildOrderBookView() {
    if (_asks.isEmpty && _bids.isEmpty) {
      return const Center(child: Text('Loading live Order Book...', style: TextStyle(color: Colors.white38, fontSize: 12)));
    }
    final maxQty = [..._asks, ..._bids].map((e) => e.qty).fold<double>(0.0001, max);
    return Row(
      children: [
        Expanded(
          child: ListView(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            children: [
              const Text('BIDS (Buy Orders)', style: TextStyle(color: Color(0xFF00E5A0), fontSize: 10, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              ..._bids.map((b) => _bookRow(b, maxQty, true)),
            ],
          ),
        ),
        const VerticalDivider(width: 1, color: Color(0xFF1C2333)),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            children: [
              const Text('ASKS (Sell Orders)', style: TextStyle(color: Color(0xFFEF4444), fontSize: 10, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              ..._asks.map((a) => _bookRow(a, maxQty, false)),
            ],
          ),
        ),
      ],
    );
  }

  Widget _bookRow(OrderBookLevel lvl, double maxQty, bool isBid) {
    final ratio = (lvl.qty / maxQty).clamp(0.05, 1.0);
    final col = isBid ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 1.5),
      child: Stack(
        children: [
          FractionallySizedBox(
            widthFactor: ratio,
            child: Container(height: 18, color: col.withValues(alpha: 0.14)),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(lvl.price.toStringAsFixed(lvl.price < 10 ? 4 : 2), style: TextStyle(color: col, fontSize: 11, fontFamily: 'monospace')),
                Text(lvl.qty.toStringAsFixed(4), style: const TextStyle(color: Colors.white70, fontSize: 11, fontFamily: 'monospace')),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTradesTable(List<MarketTrade> list) {
    if (list.isEmpty) {
      return const Center(child: Text('No trades yet', style: TextStyle(color: Colors.white38, fontSize: 12)));
    }
    return ListView.builder(
      itemCount: list.length,
      itemBuilder: (context, i) {
        final tr = list[i];
        final col = tr.isBuy ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);
        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: Row(
            children: [
              SizedBox(width: 66, child: Text(tr.time, style: const TextStyle(color: Colors.white38, fontSize: 11))),
              SizedBox(width: 46, child: Text(tr.isBuy ? 'Buy' : 'Sell', style: TextStyle(color: col, fontSize: 11, fontWeight: FontWeight.bold))),
              Expanded(child: Text('\$${tr.price.toStringAsFixed(2)}', style: const TextStyle(color: Colors.white, fontSize: 11))),
              Expanded(child: Text(tr.qty.toStringAsFixed(4), style: const TextStyle(color: Colors.white70, fontSize: 11))),
              Text('\$${tr.valueUsd.toStringAsFixed(2)}', style: TextStyle(color: col, fontSize: 11, fontWeight: FontWeight.w600)),
            ],
          ),
        );
      },
    );
  }

  Widget _buildPerpPositionsView() {
    if (_perpPositions.isEmpty) {
      return const Center(child: Text('No open Perps positions. Open a Paper Long/Short to track ROE %.', style: TextStyle(color: Colors.white38, fontSize: 12)));
    }
    return ListView.builder(
      itemCount: _perpPositions.length,
      itemBuilder: (context, i) {
        final p = _perpPositions[i];
        final mark = _tickers.where((t) => t.symbol == p.symbol).firstOrNull?.price ?? p.entryPrice;
        final diff = p.isLong ? (mark - p.entryPrice) : (p.entryPrice - mark);
        final pnl = (diff / p.entryPrice) * p.sizeUsd;
        final roe = (pnl / p.marginUsd) * 100;
        final pnlCol = pnl >= 0 ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);

        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF1C2333)))),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text('${p.symbol}-PERP', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                        const SizedBox(width: 6),
                        Text(
                          '${p.isLong ? "LONG" : "SHORT"} ${p.leverage}x',
                          style: TextStyle(color: p.isLong ? const Color(0xFF00E5A0) : const Color(0xFFEF4444), fontSize: 11, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    Text(
                      'Size: \$${p.sizeUsd.toStringAsFixed(0)} • Entry: \$${p.entryPrice.toStringAsFixed(2)} • Liq: \$${p.liqPrice.toStringAsFixed(2)}',
                      style: const TextStyle(color: Colors.white54, fontSize: 10),
                    ),
                  ],
                ),
              ),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text('${pnl >= 0 ? '+' : ''}\$${pnl.toStringAsFixed(2)} (${roe.toStringAsFixed(1)}%)', style: TextStyle(color: pnlCol, fontWeight: FontWeight.bold, fontSize: 11)),
                  const SizedBox(height: 4),
                  InkWell(
                    onTap: () => _closePerpPosition(p),
                    child: const Text('Close Position', style: TextStyle(color: Color(0xFF38BDF8), fontSize: 10, fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildRightExecutionPanel({bool scrollable = true}) {
    final price = _activeTicker?.price ?? 0;
    final margin = double.tryParse(_amountCtrl.text.trim()) ?? 0;
    final orderVal = _isPerpsMode ? (margin * _leverage) : margin;
    final liqEst = _calcLiqPrice(price, _leverage, _isLongOrBuy);

    final content = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            _orderSideBtn(_isPerpsMode ? 'Long' : 'Buy', _isLongOrBuy, const Color(0xFF00E5A0), () => setState(() => _isLongOrBuy = true)),
            const SizedBox(width: 6),
            _orderSideBtn(_isPerpsMode ? 'Short' : 'Sell', !_isLongOrBuy, const Color(0xFFEF4444), () => setState(() => _isLongOrBuy = false)),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            const Text('Available Margin', style: TextStyle(color: Colors.white54, fontSize: 11)),
            Text('\$${_paperUsdt.toStringAsFixed(2)}', style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
          ],
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _amountCtrl,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          onChanged: (_) => setState(() {}),
          style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold),
          decoration: InputDecoration(
            isDense: true,
            suffixText: 'USDT',
            suffixStyle: const TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold),
            filled: true,
            fillColor: const Color(0xFF141B29),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: Color(0xFF1F2937))),
          ),
        ),
        const SizedBox(height: 10),
        if (_isPerpsMode) ...[
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('Leverage', style: TextStyle(color: Colors.white60, fontSize: 11)),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(color: const Color(0xFF1E293B), borderRadius: BorderRadius.circular(6)),
                child: Text('${_leverage}x', style: const TextStyle(color: Color(0xFF00E5A0), fontSize: 11, fontWeight: FontWeight.bold)),
              ),
            ],
          ),
          Slider(
            value: _leverage.toDouble(),
            min: 1,
            max: 40,
            divisions: 39,
            activeColor: const Color(0xFF00E5A0),
            onChanged: (v) => setState(() => _leverage = v.round()),
          ),
          _infoRow('Liquidation Price Est.', liqEst > 0 ? '\$${liqEst.toStringAsFixed(2)}' : 'N/A', const Color(0xFFF59E0B)),
          const SizedBox(height: 4),
          _infoRow('Order Value', '\$${orderVal.toStringAsFixed(2)}', Colors.white),
          const SizedBox(height: 4),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('Auto Close (TP/SL)', style: TextStyle(color: Colors.white60, fontSize: 11)),
              Transform.scale(
                scale: 0.75,
                child: Switch(
                  value: _autoClose,
                  activeThumbColor: const Color(0xFF00E5A0),
                  onChanged: (v) => setState(() => _autoClose = v),
                ),
              ),
            ],
          ),
        ],
        const SizedBox(height: 10),
        ElevatedButton(
          onPressed: _executeOrder,
          style: ElevatedButton.styleFrom(
            backgroundColor: _isLongOrBuy ? const Color(0xFF00E5A0) : const Color(0xFFEF4444),
            foregroundColor: const Color(0xFF070B14),
            padding: const EdgeInsets.symmetric(vertical: 12),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
          ),
          child: Text(
            '${_paperMode ? "Paper " : ""}${_isPerpsMode ? (_isLongOrBuy ? "Open Long" : "Open Short") : (_isLongOrBuy ? "Buy" : "Sell")} $_baseCoin',
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
          ),
        ),
        InkWell(
          onTap: () => setState(() => _showFeeDetails = !_showFeeDetails),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Text('\$0 Gas (Paymaster) • 0.1% Fee • Details', style: TextStyle(color: Colors.white54, fontSize: 10)),
                Icon(_showFeeDetails ? Icons.expand_less : Icons.expand_more, color: Colors.white54, size: 14),
              ],
            ),
          ),
        ),
        if (_showFeeDetails)
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(color: const Color(0xFF141B29), borderRadius: BorderRadius.circular(8)),
            child: const Text(
              'Network Gas: \$0.00 (Paymaster Sponsored)\nExecution Fee: 0.10% (Transparent)',
              style: TextStyle(color: Colors.white60, fontSize: 10, height: 1.4),
            ),
          ),
      ],
    );

    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF0B0F17),
        border: Border(left: BorderSide(color: Color(0xFF1C2333))),
      ),
      padding: const EdgeInsets.all(12),
      child: scrollable ? SingleChildScrollView(child: content) : content,
    );
  }

  Widget _infoRow(String label, String val, Color col) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(color: Colors.white54, fontSize: 11)),
        Text(val, style: TextStyle(color: col, fontSize: 11, fontWeight: FontWeight.bold)),
      ],
    );
  }

  Widget _miniTab(String label, bool active, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(right: 12),
        padding: const EdgeInsets.only(bottom: 4),
        decoration: BoxDecoration(
          border: Border(bottom: BorderSide(color: active ? const Color(0xFF00E5A0) : Colors.transparent, width: 2)),
        ),
        child: Text(label, style: TextStyle(color: active ? Colors.white : Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
      ),
    );
  }

  Widget _orderSideBtn(String label, bool active, Color col, VoidCallback onTap) {
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            color: active ? col.withValues(alpha: 0.18) : const Color(0xFF141B29),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: active ? col : Colors.transparent),
          ),
          alignment: Alignment.center,
          child: Text(label, style: TextStyle(color: active ? col : Colors.white54, fontWeight: FontWeight.bold, fontSize: 12)),
        ),
      ),
    );
  }
}

class _PerpsChartPainter extends CustomPainter {
  final List<CandlePoint> candles;
  _PerpsChartPainter(this.candles);

  @override
  void paint(Canvas canvas, Size size) {
    if (candles.isEmpty) return;
    const axisW = 58.0;
    final plotW = (size.width - axisW).clamp(50.0, size.width);
    final chartH = size.height * 0.78;
    final volH = size.height * 0.18;

    double minP = candles.map((c) => c.low).reduce(min);
    double maxP = candles.map((c) => c.high).reduce(max);
    final range = (maxP - minP).abs() < 1e-6 ? 1.0 : (maxP - minP);
    double maxVol = candles.map((c) => c.volume).reduce(max);
    if (maxVol <= 0) maxVol = 1.0;

    final gridPaint = Paint()..color = const Color(0xFF1A2232)..strokeWidth = 0.7;
    for (int i = 0; i <= 4; i++) {
      final y = chartH * i / 4;
      canvas.drawLine(Offset(0, y), Offset(plotW, y), gridPaint);
      final priceAtY = maxP - (range * i / 4);
      final tp = TextPainter(
        text: TextSpan(
          text: priceAtY.toStringAsFixed(priceAtY < 10 ? 3 : 2),
          style: const TextStyle(color: Colors.white38, fontSize: 9),
        ),
        textDirection: TextDirection.ltr,
      )..layout();
      tp.paint(canvas, Offset(plotW + 6, y - 5));
    }

    final step = plotW / candles.length;
    final bodyW = (step * 0.64).clamp(2.2, 8.5);
    double yOf(double p) => chartH - ((p - minP) / range) * (chartH - 12) - 6;

    for (int i = 0; i < candles.length; i++) {
      final c = candles[i];
      final x = i * step + step / 2;
      final bull = c.close >= c.open;
      final col = bull ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);

      canvas.drawLine(Offset(x, yOf(c.high)), Offset(x, yOf(c.low)), Paint()..color = col..strokeWidth = 1.1);
      final top = yOf(max(c.open, c.close));
      final bot = yOf(min(c.open, c.close));
      canvas.drawRect(Rect.fromLTRB(x - bodyW / 2, top, x + bodyW / 2, max(bot, top + 1.4)), Paint()..color = col);

      final barH = (c.volume / maxVol) * volH;
      canvas.drawRect(
        Rect.fromLTRB(x - bodyW / 2, size.height - barH, x + bodyW / 2, size.height),
        Paint()..color = col.withValues(alpha: 0.32),
      );
    }

    final last = candles.last;
    final lastY = yOf(last.close);
    final pillCol = last.close >= last.open ? const Color(0xFF00E5A0) : const Color(0xFFEF4444);
    canvas.drawLine(Offset(0, lastY), Offset(plotW, lastY), Paint()..color = pillCol.withValues(alpha: 0.5)..strokeWidth = 0.9);
    canvas.drawRRect(
      RRect.fromRectAndRadius(Rect.fromLTWH(plotW + 2, lastY - 8, axisW - 4, 16), const Radius.circular(4)),
      Paint()..color = pillCol,
    );
    final tpLast = TextPainter(
      text: TextSpan(
        text: last.close.toStringAsFixed(last.close < 10 ? 3 : 2),
        style: const TextStyle(color: Color(0xFF070B14), fontSize: 9, fontWeight: FontWeight.bold),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    tpLast.paint(canvas, Offset(plotW + 6, lastY - 5));
  }

  @override
  bool shouldRepaint(covariant _PerpsChartPainter oldDelegate) => oldDelegate.candles != candles;
}