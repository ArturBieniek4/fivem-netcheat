#include "mainwindow.h"

#include "editdialog.h"
#include "eventmodel.h"
#include "sniffereventsource.h"

#include <QAction>
#include <QFile>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTableView>
#include <QToolBar>
#include <QVBoxLayout>

namespace {

const char kPortFileEnvVar[] = "EVENT_INSPECTOR_PORT_FILE";
const char kDefaultPortFile[] = "inspector_port.txt";

class RowActionsWidget final : public QWidget {
public:
  explicit RowActionsWidget(qint64 evId, QWidget *parent = nullptr)
      : QWidget(parent), m_id(evId) {
    m_editBtn = new QPushButton("Edit", this);
    m_resendBtn = new QPushButton("Resend", this);

    m_editBtn->setMaximumWidth(70);
    m_resendBtn->setMaximumWidth(80);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    layout->addWidget(m_editBtn);
    layout->addWidget(m_resendBtn);
  }

  qint64 id() const { return m_id; }
  QPushButton *editButton() const { return m_editBtn; }
  QPushButton *resendButton() const { return m_resendBtn; }

private:
  qint64 m_id;
  QPushButton *m_editBtn = nullptr;
  QPushButton *m_resendBtn = nullptr;
};

} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setWindowTitle("Event Inspector");
  resize(1200, 700);

  m_model = new EventModel(this);
  m_snifferSource = new SnifferEventSource(this);

  // --- Toolbar: filter + controls
  auto *tb = addToolBar("Main");
  tb->setMovable(false);

  tb->addWidget(new QLabel("Filter:", this));
  m_filter = new QLineEdit(this);
  m_filter->setPlaceholderText("name or payload...");
  m_filter->setClearButtonEnabled(true);
  m_filter->setMaximumWidth(380);
  tb->addWidget(m_filter);

  auto *clearAct = tb->addAction("Clear");
  connect(clearAct, &QAction::triggered, this, [this] {
    m_model->clear();
    m_summary->setText("Select an event to see details.");
    m_payloadView->clear();
    m_rawView->clear();
  });

  connect(m_filter, &QLineEdit::textChanged, this,
          &MainWindow::onFilterTextChanged);

  // --- Left: table
  m_table = new QTableView(this);
  m_table->setModel(m_model);
  m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_table->setSelectionMode(QAbstractItemView::SingleSelection);
  m_table->setAlternatingRowColors(true);
  m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  m_table->verticalHeader()->setVisible(false);
  m_table->horizontalHeader()->setStretchLastSection(true);

  m_table->setColumnWidth(EventModel::TimeCol, 115);
  m_table->setColumnWidth(EventModel::DirCol, 55);
  m_table->setColumnWidth(EventModel::NameCol, 240);
  m_table->setColumnWidth(EventModel::SizeCol, 70);
  m_table->setColumnWidth(EventModel::StatusCol, 110);
  m_table->setColumnWidth(EventModel::ActionsCol, 170);

  // --- Right: details
  auto *details = new QWidget(this);
  auto *detailsLayout = new QVBoxLayout(details);
  detailsLayout->setContentsMargins(8, 8, 8, 8);

  m_summary = new QLabel("Select an event to see details.", details);
  m_summary->setWordWrap(true);

  auto *tabs = new QTabWidget(details);
  m_payloadView = new QPlainTextEdit(details);
  m_payloadView->setReadOnly(true);
  m_payloadView->setPlaceholderText("Payload...");

  m_rawView = new QPlainTextEdit(details);
  m_rawView->setReadOnly(true);
  m_rawView->setPlaceholderText("Raw bytes (hex)...");

  tabs->addTab(m_payloadView, "Payload");
  tabs->addTab(m_rawView, "Raw");

  detailsLayout->addWidget(m_summary);
  detailsLayout->addWidget(tabs, 1);

  // --- Splitter
  auto *split = new QSplitter(Qt::Horizontal, this);
  split->addWidget(m_table);
  split->addWidget(details);
  split->setStretchFactor(0, 3);
  split->setStretchFactor(1, 2);
  setCentralWidget(split);

  // --- Signals
  connect(m_snifferSource, &SnifferEventSource::eventCaptured, this,
          &MainWindow::onEventCaptured);
  connect(m_snifferSource, &SnifferEventSource::error, this,
          [this](const QString &msg) { m_summary->setText(msg); });
  connect(m_snifferSource, &SnifferEventSource::listening, this,
          [this](quint16 port) {
            QString filePath = qEnvironmentVariable(kPortFileEnvVar);
            if (filePath.isEmpty()) {
              filePath = QStandardPaths::writableLocation(
                  QStandardPaths::TempLocation);
              if (!filePath.isEmpty()) {
                filePath += QLatin1Char('/');
                filePath += kDefaultPortFile;
              } else {
                filePath = kDefaultPortFile;
              }
            }

            QFile file(filePath);
            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate |
                          QIODevice::Text)) {
              file.write(QByteArray::number(port));
            } else {
              m_summary->setText(
                  QString("Failed to write port file: %1").arg(filePath));
            }
          });
  connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged,
          this, &MainWindow::onSelectionChanged);

  m_snifferSource->start();
}

void MainWindow::onEventCaptured(NetEvent ev) {
  const int rowBefore = m_model->rowCount();
  m_model->addEvent(std::move(ev));
  const int row = rowBefore;
  refreshRowActionsWidget(row);

  // Autoscroll to bottom.
  m_table->scrollToBottom();

  // Apply current filter to the new row.
  onFilterTextChanged(m_filter->text());
}

void MainWindow::refreshRowActionsWidget(int row) {
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev)
    return;

  auto *w = new RowActionsWidget(ev->id, m_table);
  connect(w->editButton(), &QPushButton::clicked, this,
          [this, id = ev->id] { onEditEvent(id); });
  connect(w->resendButton(), &QPushButton::clicked, this,
          [this, id = ev->id] { onResendEvent(id); });

  const QModelIndex idx = m_model->index(row, EventModel::ActionsCol);
  m_table->setIndexWidget(idx, w);
}

void MainWindow::onSelectionChanged() {
  const QModelIndexList rows = m_table->selectionModel()->selectedRows();
  if (rows.isEmpty()) {
    m_summary->setText("Select an event to see details.");
    m_payloadView->clear();
    m_rawView->clear();
    return;
  }
  updateDetailsForRow(rows.first().row());
}

void MainWindow::updateDetailsForRow(int row) {
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev)
    return;

  m_summary->setText(QString("[%1] %2  %3  (%4 bytes)\nstatus: %5")
                         .arg(ev->time.toString("yyyy-MM-dd HH:mm:ss.zzz"))
                         .arg(ev->direction)
                         .arg(ev->name)
                         .arg(ev->payloadUtf8.size())
                         .arg(ev->status));

  m_payloadView->setPlainText(QString::fromUtf8(ev->payloadUtf8));

  if (ev->rawBytes.isEmpty()) {
    m_rawView->setPlainText("");
  } else {
    m_rawView->setPlainText(QString::fromLatin1(ev->rawBytes.toHex(' ')));
  }
}

void MainWindow::onFilterTextChanged(const QString &text) {
  const QString needle = text.trimmed();
  for (int row = 0; row < m_model->rowCount(); ++row) {
    const NetEvent *ev = m_model->eventAtRow(row);
    if (!ev)
      continue;

    const bool match = needle.isEmpty() ||
                       ev->name.contains(needle, Qt::CaseInsensitive) ||
                       QString::fromUtf8(ev->payloadUtf8)
                           .contains(needle, Qt::CaseInsensitive);

    m_table->setRowHidden(row, !match);
  }
}

void MainWindow::onEditEvent(qint64 id) {
  const int row = m_model->rowForId(id);
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev)
    return;

  auto *dlg = new EditDialog(*ev, this);
  connect(dlg, &EditDialog::sendRequested, this, &MainWindow::onSendRequested);
  dlg->open();
}

void MainWindow::onResendEvent(qint64 id) {
  const int row = m_model->rowForId(id);
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev)
    return;

  QJsonObject cmd;
  cmd["type"] = "command";
  cmd["command"] = "resend";
  cmd["id"] = static_cast<qint64>(ev->id);
  cmd["name"] = ev->name;
  cmd["direction"] = ev->direction;
  cmd["payload_utf8"] = QString::fromUtf8(ev->payloadUtf8);
  sendCommandToSniffer(cmd);

  NetEvent out = *ev;
  out.time = QDateTime::currentDateTime();
  out.direction = ev->direction;
  out.status = "sent (resend)";

  m_model->addEvent(std::move(out));
  refreshRowActionsWidget(m_model->rowCount() - 1);
}

void MainWindow::onSendRequested(NetEvent ev) {
  QJsonObject cmd;
  cmd["type"] = "command";
  cmd["command"] = "send";
  cmd["name"] = ev.name;
  cmd["direction"] = ev.direction;
  cmd["payload_utf8"] = QString::fromUtf8(ev.payloadUtf8);
  sendCommandToSniffer(cmd);

  ev.time = QDateTime::currentDateTime();
  ev.status = "sent (edited)";

  m_model->addEvent(std::move(ev));
  refreshRowActionsWidget(m_model->rowCount() - 1);
}

void MainWindow::sendCommandToSniffer(const QJsonObject &obj) {
  if (!m_snifferSource)
    return;
  m_snifferSource->sendCommand(obj);
}
