#pragma once

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>

#include "eventtypes.h"

class QJsonObject;

class SnifferEventSource final : public QObject {
  Q_OBJECT
public:
  explicit SnifferEventSource(QObject *parent = nullptr);

  bool start();
  void stop();
  void sendCommand(const QJsonObject &obj);

signals:
  void eventCaptured(NetEvent ev);
  void error(const QString &message);
  void listening(quint16 port);

private slots:
  void onNewConnection();
  void onReadyRead();
  void onClientDisconnected();

private:
  QTcpServer m_server;
  QTcpSocket *m_client = nullptr;
  QByteArray m_buffer;
  quint64 m_counter = 0;
};
