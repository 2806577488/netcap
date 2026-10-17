// Why this exists: the 过滤日志 page used to show *either* the live events
// *or* the durable file — the file won whenever it was non-empty, so right
// after a session the page showed an older session's rows and looked stale
// (the user asked "这对吗？" about exactly that).  The page now shows both.
import 'models.dart';

/// The same decision seen twice — once as a live event, once read back from
/// `filter-log.jsonl` — must not appear twice.  Microsecond timestamps make
/// this exact, and they are also what the sort uses.
String filterLogKey(InterceptRecord r) =>
    '${r.tsUs}|${r.action}|${r.host}|${r.url}';

/// Live events plus file-only rows, newest first, duplicates dropped.
List<InterceptRecord> mergeFilterLog(
  List<InterceptRecord> live,
  List<InterceptRecord> fromFile,
) {
  final merged = <InterceptRecord>[...live];
  final seen = merged.map(filterLogKey).toSet();
  for (final r in fromFile) {
    if (seen.add(filterLogKey(r))) merged.add(r);
  }
  merged.sort((a, b) => b.tsUs.compareTo(a.tsUs));
  return merged;
}
