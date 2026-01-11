#include "sniffereventsource.h"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

namespace {

QByteArray payloadToUtf8(const QJsonValue &value) {
  if (value.isUndefined() || value.isNull())
    return {};

  if (value.isString())
    return value.toString().toUtf8();

  if (value.isObject()) {
    return QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact);
  }

  if (value.isArray()) {
    return QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact);
  }

  QJsonObject wrapper;
  wrapper.insert("value", value);
  return QJsonDocument(wrapper).toJson(QJsonDocument::Compact);
}

QByteArray hexToBytes(const QString &hex) {
  if (hex.isEmpty())
    return {};
  QString cleaned = hex;
  cleaned.remove(' ');
  return QByteArray::fromHex(cleaned.toLatin1());
}

} // namespace

SnifferEventSource::SnifferEventSource(QObject *parent) : QObject(parent) {
  connect(&m_server, &QTcpServer::newConnection, this,
          &SnifferEventSource::onNewConnection);
}

bool SnifferEventSource::start() {
  if (m_server.isListening())
    return true;

  if (!m_server.listen(QHostAddress::LocalHost, 0)) {
    emit error(
        QString("Failed to start TCP server: %1").arg(m_server.errorString()));
    return false;
  }

  emit listening(m_server.serverPort());
  return true;
}

void SnifferEventSource::stop() {
  if (m_client) {
    m_client->disconnect(this);
    m_client->close();
    m_client->deleteLater();
    m_client = nullptr;
  }
  m_server.close();
  m_buffer.clear();
}

void SnifferEventSource::sendCommand(const QJsonObject &obj) {
  if (!m_client || m_client->state() != QAbstractSocket::ConnectedState)
    return;
  QJsonDocument doc(obj);
  QByteArray payload = doc.toJson(QJsonDocument::Compact);
  payload.append('\n');
  m_client->write(payload);
}

void SnifferEventSource::onNewConnection() {
  QTcpSocket *client = m_server.nextPendingConnection();
  if (!client)
    return;

  if (m_client) {
    m_client->disconnect(this);
    m_client->close();
    m_client->deleteLater();
  }

  m_client = client;
  m_buffer.clear();

  connect(m_client, &QTcpSocket::readyRead, this,
          &SnifferEventSource::onReadyRead);
  connect(m_client, &QTcpSocket::disconnected, this,
          &SnifferEventSource::onClientDisconnected);
}

void SnifferEventSource::onClientDisconnected() {
  if (!m_client)
    return;
  m_client->deleteLater();
  m_client = nullptr;
  m_buffer.clear();
}

void SnifferEventSource::onReadyRead() {
  if (!m_client)
    return;
  m_buffer.append(m_client->readAll());

  while (true) {
    const int newline = m_buffer.indexOf('\n');
    if (newline < 0)
      break;

    const QByteArray line = m_buffer.left(newline).trimmed();
    m_buffer.remove(0, newline + 1);
    if (line.isEmpty())
      continue;

    QJsonParseError parseError{};
    QJsonDocument doc = QJsonDocument::fromJson(line, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject())
      continue;

    const QJsonObject obj = doc.object();
    if (obj.value("type").toString() != "event")
      continue;

    NetEvent ev;
    ev.time = QDateTime::currentDateTime();
    ev.direction = obj.value("direction").toString("IN");
    ev.name = obj.value("name").toString("Unknown");
    ev.payloadUtf8 = payloadToUtf8(obj.value("payload"));
    if (ev.payloadUtf8.isEmpty()) {
      ev.payloadUtf8 = obj.value("payload_utf8").toString().toUtf8();
    }
    ev.rawBytes = hexToBytes(obj.value("raw_hex").toString());
    ev.status = obj.value("status").toString("captured");

    emit eventCaptured(std::move(ev));
  }
}
