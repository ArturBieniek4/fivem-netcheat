#pragma once

#include <QAbstractTableModel>
#include <QVector>

#include "eventtypes.h"

class EventModel final : public QAbstractTableModel {
  Q_OBJECT
public:
  enum Column {
    TimeCol = 0,
    DirCol,
    NameCol,
    SizeCol,
    StatusCol,
    ActionsCol,
    ColumnCount
  };

  explicit EventModel(QObject *parent = nullptr);

  int rowCount(const QModelIndex &parent = QModelIndex()) const override;
  int columnCount(const QModelIndex &parent = QModelIndex()) const override;
  QVariant data(const QModelIndex &index, int role) const override;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
  Qt::ItemFlags flags(const QModelIndex &index) const override;

  void addEvent(NetEvent ev);
  bool updateEventById(qint64 id, const NetEvent &ev);

  void clear();

  const NetEvent *eventAtRow(int row) const;
  NetEvent *eventAtRow(int row);

  int rowForId(qint64 id) const;

private:
  QVector<NetEvent> m_events;
  qint64 m_nextId = 1;
};
