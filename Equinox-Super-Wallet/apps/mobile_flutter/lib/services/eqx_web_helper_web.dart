// ignore: avoid_web_libraries_in_flutter
import 'dart:html' as html;

void openFullTab() {
  html.window.open(html.window.location.href, '_blank');
}
