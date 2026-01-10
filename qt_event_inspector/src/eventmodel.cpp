#include "eventmodel.h"

#include <QBrush>
#include <QFont>

EventModel::EventModel(QObject *parent) : QAbstractTableModel(parent) {}

int EventModel::rowCount(const QModelIndex &parent) const {
  if (parent.isValid()) return 0;
  return m_events.size();
}

int EventModel::columnCount(const QModelIndex &parent) const {
  if (parent.isValid()) return 0;
  return ColumnCount;
}

QVariant EventModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid()) return {};
  const int row = index.row();
  const int col = index.column();
  if (row < 0 || row >= m_events.size()) return {};
  const NetEvent &ev = m_events[row];

  if (role == Qt::DisplayRole) {
    switch (col) {
      case TimeCol: return ev.time.toString("HH:mm:ss.zzz");
      case DirCol: return ev.direction;
      case NameCol: return ev.name;
      case SizeCol: return QString::number(ev.payloadUtf8.size());
      case StatusCol: return ev.status;
      case ActionsCol: return QString();
      default: return {};
    }
  }

  if (role == Qt::ToolTipRole) {
    if (col == NameCol) return ev.name;
    if (col == StatusCol) return ev.status;
    if (col == SizeCol) return QString("%1 bytes").arg(ev.payloadUtf8.size());
  }

  if (role == Qt::FontRole) {
    if (col == DirCol) {
      QFont f;
      f.setBold(true);
      return f;
    }
  }

  if (role == Qt::ForegroundRole) {
    if (col == DirCol) {
      if (ev.direction == "IN") return QBrush(Qt::darkGreen);
      if (ev.direction == "OUT") return QBrush(Qt::darkBlue);
    }
    if (col == StatusCol) {
      if (ev.status.contains("error", Qt::CaseInsensitive)) return QBrush(Qt::darkRed);
    }
  }

  return {};
}

QVariant EventModel::headerData(int section, Qt::Orientation orientation, int role) const {
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
  switch (section) {
    case TimeCol: return "Time";
    case DirCol: return "Dir";
    case NameCol: return "Name";
    case SizeCol: return "Size";
    case StatusCol: return "Status";
    case ActionsCol: return "Actions";
    default: return {};
  }
}

Qt::ItemFlags EventModel::flags(const QModelIndex &index) const {
  if (!index.isValid()) return Qt::NoItemFlags;
  return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

void EventModel::addEvent(NetEvent ev) {
  ev.id = m_nextId++;
  if (!ev.time.isValid()) ev.time = QDateTime::currentDateTime();

  const int row = m_events.size();
  beginInsertRows(QModelIndex(), row, row);
  m_events.push_back(std::move(ev));
  endInsertRows();
}

bool EventModel::updateEventById(qint64 id, const NetEvent &ev) {
  const int row = rowForId(id);
  if (row < 0) return false;
  m_events[row] = ev;
  m_events[row].id = id; // keep stable id
  emit dataChanged(index(row, 0), index(row, ColumnCount - 1));
  return true;
}

const NetEvent *EventModel::eventAtRow(int row) const {
  if (row < 0 || row >= m_events.size()) return nullptr;
  return &m_events[row];
}

NetEvent *EventModel::eventAtRow(int row) {
  if (row < 0 || row >= m_events.size()) return nullptr;
  return &m_events[row];
}

int EventModel::rowForId(qint64 id) const {
  for (int i = 0; i < m_events.size(); ++i) {
    if (m_events[i].id == id) return i;
  }
  return -1;
}

void EventModel::clear() {
  beginResetModel();
  m_events.clear();
  m_nextId = 1;
  endResetModel();
}
