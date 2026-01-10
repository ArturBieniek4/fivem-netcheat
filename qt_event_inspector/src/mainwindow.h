#pragma once

#include <QMainWindow>

#include "eventtypes.h"

class QLineEdit;
class QPlainTextEdit;
class QTableView;
class QLabel;

class EventModel;
class DummyEventSource;

class MainWindow final : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget *parent = nullptr);

private slots:
  void onEventCaptured(NetEvent ev);
  void onSelectionChanged();
  void onFilterTextChanged(const QString &text);

  void onEditEvent(qint64 id);
  void onResendEvent(qint64 id);
  void onSendRequested(NetEvent ev);

private:
  void updateDetailsForRow(int row);
  void refreshRowActionsWidget(int row);

  EventModel *m_model = nullptr;
  DummyEventSource *m_source = nullptr;

  QTableView *m_table = nullptr;
  QLineEdit *m_filter = nullptr;

  QPlainTextEdit *m_payloadView = nullptr;
  QPlainTextEdit *m_rawView = nullptr;
  QLabel *m_summary = nullptr;
};
