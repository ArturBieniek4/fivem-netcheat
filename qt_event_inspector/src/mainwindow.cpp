#include "mainwindow.h"

#include "dummyeventsource.h"
#include "editdialog.h"
#include "eventmodel.h"

#include <QAction>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTableView>
#include <QTabWidget>
#include <QToolBar>
#include <QVBoxLayout>

namespace {

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
  setWindowTitle("Event Inspector (Qt prototype)");
  resize(1200, 700);

  m_model = new EventModel(this);
  m_source = new DummyEventSource(this);

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
  auto *genAct = tb->addAction("Generate");
  genAct->setToolTip("Start/stop dummy event stream");

  connect(clearAct, &QAction::triggered, this, [this] {
    m_model->clear();
    m_summary->setText("Select an event to see details.");
    m_payloadView->clear();
    m_rawView->clear();
  });

  bool running = false;
  connect(genAct, &QAction::triggered, this, [this, &running, genAct] {
    running = !running;
    genAct->setText(running ? "Stop" : "Generate");
    if (running)
      m_source->start();
    else
      m_source->stop();
  });

  connect(m_filter, &QLineEdit::textChanged, this, &MainWindow::onFilterTextChanged);

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
  connect(m_source, &DummyEventSource::eventCaptured, this, &MainWindow::onEventCaptured);
  connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, this,
          &MainWindow::onSelectionChanged);

  // Start with dummy traffic on.
  running = true;
  genAct->setText("Stop");
  m_source->start();
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
  if (!ev) return;

  auto *w = new RowActionsWidget(ev->id, m_table);
  connect(w->editButton(), &QPushButton::clicked, this, [this, id = ev->id] { onEditEvent(id); });
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
  if (!ev) return;

  m_summary->setText(QString("[%1] %2  %3  (%4 bytes)\nstatus: %5")
                         .arg(ev->time.toString("yyyy-MM-dd HH:mm:ss.zzz"))
                         .arg(ev->direction)
                         .arg(ev->name)
                         .arg(ev->payloadUtf8.size())
                         .arg(ev->status));

  m_payloadView->setPlainText(QString::fromUtf8(ev->payloadUtf8));

  if (ev->rawBytes.isEmpty()) {
    m_rawView->setPlainText("(no raw bytes in this prototype)");
  } else {
    m_rawView->setPlainText(QString::fromLatin1(ev->rawBytes.toHex(' ')));
  }
}

void MainWindow::onFilterTextChanged(const QString &text) {
  const QString needle = text.trimmed();
  for (int row = 0; row < m_model->rowCount(); ++row) {
    const NetEvent *ev = m_model->eventAtRow(row);
    if (!ev) continue;

    const bool match = needle.isEmpty() || ev->name.contains(needle, Qt::CaseInsensitive) ||
                       QString::fromUtf8(ev->payloadUtf8)
                           .contains(needle, Qt::CaseInsensitive);

    m_table->setRowHidden(row, !match);
  }
}

void MainWindow::onEditEvent(qint64 id) {
  const int row = m_model->rowForId(id);
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev) return;

  auto *dlg = new EditDialog(*ev, this);
  connect(dlg, &EditDialog::sendRequested, this, &MainWindow::onSendRequested);
  dlg->open();
}

void MainWindow::onResendEvent(qint64 id) {
  const int row = m_model->rowForId(id);
  const NetEvent *ev = m_model->eventAtRow(row);
  if (!ev) return;

  NetEvent out = *ev;
  out.time = QDateTime::currentDateTime();
  out.direction = "OUT";
  out.status = "sent (resend)";

  m_model->addEvent(std::move(out));
  refreshRowActionsWidget(m_model->rowCount() - 1);
}

void MainWindow::onSendRequested(NetEvent ev) {
  // In a real app: call your authorized backend.
  // In this prototype: append it to the log as OUT.
  ev.time = QDateTime::currentDateTime();
  ev.direction = "OUT";
  ev.status = "sent (edited)";

  m_model->addEvent(std::move(ev));
  refreshRowActionsWidget(m_model->rowCount() - 1);
}
