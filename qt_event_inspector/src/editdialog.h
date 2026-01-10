#pragma once

#include <QDialog>

#include "eventtypes.h"

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QLabel;

class EditDialog final : public QDialog {
  Q_OBJECT
public:
  explicit EditDialog(const NetEvent &ev, QWidget *parent = nullptr);

  NetEvent editedEvent() const;

signals:
  void sendRequested(NetEvent ev);

private slots:
  void onSend();

private:
  NetEvent m_original;

  QLineEdit *m_name = nullptr;
  QComboBox *m_dir = nullptr;
  QPlainTextEdit *m_payload = nullptr;
  QLabel *m_hint = nullptr;
};
