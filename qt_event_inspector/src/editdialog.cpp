#include "editdialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

EditDialog::EditDialog(const NetEvent &ev, QWidget *parent)
    : QDialog(parent), m_original(ev) {
  setWindowTitle("Edit & Send");
  setModal(true);
  resize(650, 420);

  m_name = new QLineEdit(ev.name, this);
  m_dir = new QComboBox(this);
  m_dir->addItems({"IN", "OUT"});
  m_dir->setCurrentText(ev.direction.isEmpty() ? "OUT" : ev.direction);

  m_payload = new QPlainTextEdit(this);
  m_payload->setPlainText(QString::fromUtf8(ev.payloadUtf8));
  m_payload->setPlaceholderText("Payload (e.g. JSON)...");

  auto *form = new QFormLayout;
  form->addRow("Name:", m_name);
  form->addRow("Direction:", m_dir);

  auto *buttons = new QDialogButtonBox(this);
  auto *sendBtn = buttons->addButton("Send", QDialogButtonBox::AcceptRole);
  buttons->addButton(QDialogButtonBox::Cancel);

  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  connect(sendBtn, &QPushButton::clicked, this, &EditDialog::onSend);

  auto *layout = new QVBoxLayout(this);
  layout->addLayout(form);
  layout->addWidget(new QLabel("Payload:", this));
  layout->addWidget(m_payload, 1);
  layout->addWidget(buttons);
}

NetEvent EditDialog::editedEvent() const {
  NetEvent ev = m_original;
  ev.name = m_name->text();
  ev.direction = m_dir->currentText();
  ev.payloadUtf8 = m_payload->toPlainText().toUtf8();
  // time/status will be set by caller when sending
  return ev;
}

void EditDialog::onSend() {
  NetEvent ev = editedEvent();
  emit sendRequested(std::move(ev));
  accept();
}
