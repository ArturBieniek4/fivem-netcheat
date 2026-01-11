#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>

struct NetEvent {
  qint64 id = 0;          // unique id for stable references
  QDateTime time;         // when captured/created
  QString direction;      // "IN" or "OUT"
  QString name;           // event name
  QByteArray payloadUtf8; // payload as UTF-8 (usually JSON for UI)
  QByteArray rawBytes;    // raw bytes (optional)
  QString status;         // e.g. "captured", "sent", "error"
};
