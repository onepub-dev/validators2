// Helper functions for validator and sanitizer.

String shift(List<String> l) {
  if (l.isNotEmpty) {
    final first = l.first;
    l.removeAt(0);
    return first;
  }
  return '';
}

Map<String, bool> merge(Map<String, bool> obj, Map<String, bool> defaults) {
  final merged = <String, bool>{};
  obj.forEach((key, val) => merged.putIfAbsent(key, () => val));
  defaults.forEach((key, val) => merged.putIfAbsent(key, () => val));
  return obj;
}
