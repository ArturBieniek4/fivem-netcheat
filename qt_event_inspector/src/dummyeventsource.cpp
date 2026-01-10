#include "dummyeventsource.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>

DummyEventSource::DummyEventSource(QObject *parent) : QObject(parent) {
  connect(&m_timer, &QTimer::timeout, this, &DummyEventSource::onTick);
}

void DummyEventSource::start(int intervalMs) {
  m_timer.start(intervalMs);
}

void DummyEventSource::stop() {
  m_timer.stop();
}

void DummyEventSource::onTick() {
  ++m_counter;

  static const QStringList names = {
    "PlayerJoined",
    "ChatMessage",
    "InventoryUpdate",
    "PositionSync",
    "Ping",
    "CustomEvent"
  };

  const QString name = names.at(QRandomGenerator::global()->bounded(names.size()));
  const QString dir = (QRandomGenerator::global()->bounded(100) < 75) ? "IN" : "OUT";

  QJsonObject payload;
  payload["seq"] = static_cast<qint64>(m_counter);
  payload["name"] = name;
  payload["ok"] = true;
  payload["value"] = QRandomGenerator::global()->bounded(1000);
  payload["tags"] = QJsonArray{ "dev", "test" };

  const QByteArray payloadUtf8 = QJsonDocument(payload).toJson(QJsonDocument::Compact);

  NetEvent ev;
  ev.time = QDateTime::currentDateTime();
  ev.direction = dir;
  ev.name = name;
  ev.payloadUtf8 = payloadUtf8;
  ev.rawBytes = QByteArray();
  ev.status = "captured";

  emit eventCaptured(std::move(ev));
}
