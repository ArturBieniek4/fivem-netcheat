#pragma once

#include <QObject>
#include <QTimer>

#include "eventtypes.h"

class DummyEventSource final : public QObject {
  Q_OBJECT
public:
  explicit DummyEventSource(QObject *parent = nullptr);

  void start(int intervalMs = 800);
  void stop();

signals:
  void eventCaptured(NetEvent ev);

private:
  void onTick();

  QTimer m_timer;
  quint64 m_counter = 0;
};
