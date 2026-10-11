import 'dart:async';

// one queued request waiting for its bundle to be sent
class _PendingRequest {
  final String action;
  final Map<String, dynamic>? body;
  final Completer<Map<String, dynamic>> completer = Completer();

  _PendingRequest(this.action, this.body);
}

class RequestBatcher {
  final int windowMs;
  final int maxBatchSize;

  //send one bundle and returns the server's list of per request results
  final Future<List<dynamic>> Function(List<Map<String, dynamic>> items) sendBatch;

  final List<_PendingRequest> _queue = [];
  Timer? _timer;

  RequestBatcher({
    required this.windowMs,
    required this.maxBatchSize,
    required this.sendBatch,
  });

  // queues a request and returns a future that completes when its bundle comes back
  Future<Map<String, dynamic>> enqueue(String action, [Map<String, dynamic>?body]) {
    final pending = _PendingRequest(action, body);
    _queue.add(pending);

    if (_queue.length >= maxBatchSize) {
      _flush(); // goes out immediately
    }
    else {
      // the first request into an empyt queu opens the window
      _timer ??= Timer(Duration(milliseconds: windowMs), _flush);
    }
    return pending.completer.future;
  }

  Future<void> _flush() async {
    _timer?.cancel();
    _timer = null;
    if (_queue.isEmpty) return;

    // snapshot first, so requests arriving during the network call start a new batch
    final batch = List<_PendingRequest>.from(_queue);
    _queue.clear();

    final items = <Map<String, dynamic>>[];
    for (var i = 0; i < batch.length; i++){
      items.add({'id': i, 'action': batch[i].action, 'body': batch[i].body});
    }

    try {
      final results = await sendBatch(items);

      final byID = <int, Map<String, dynamic>>{};
      for (final r in results) {
        byID[r['id'] as int] = r as Map<String, dynamic>;
      }

      for (var i = 0; i < batch.length; i++) {
        _settle(batch[i], byID[i]);
      }
    }
    catch(e) {
      // the whole batch failed, so every waiting caller gets the same error
      for (final pending in batch) {
        pending.completer.completeError(e);
      }
    }
  }
}

//settles one queued request from its slot in the server's response
void _settle(_PendingRequest pending, Map<String, dynamic>? result) {
  final status = result?['status'] as int?;
  final succeeded = status != null && status >= 200 && status < 300;

  if (!succeeded) {
    pending.completer.completeError(
      Exception('${pending.action} failed ${status ?? 'no response'}'),
    );
    return;
  }

  //non null status means result is not null, so the ! is safe
  pending.completer.complete(result!['body'] as Map<String, dynamic>);
}