#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    QThread::currentThread()->setObjectName(APP_NAME+"_GUI");
    ui->setupUi(this);

    // determine cache location
    m_cache_path = QDir::homePath() + QString("/.cache/") + APP_NAME + QString("/");
    m_cache_file = m_cache_path + "current_attack.kbd";

    // initital GUI setup
    ui->usersCBox->hide();
    if (!isCacheExists())
        ui->resumeButton->hide();
    ui->stopButton->hide();

    // GUI->buttons
    QObject::connect(ui->openFileButton, SIGNAL(clicked()), this, SLOT(openFileButton_clicked()), Qt::DirectConnection);

    // prepare to run updater in a separete thread
    this->m_update_thread = new QThread(this);
    this->m_updateobj = new guiUpdater(Q_NULLPTR);
    this->m_updateobj->moveToThread(this->m_update_thread);
    // updater thread <-> updater obj
    QObject::connect(this->m_update_thread, SIGNAL(started()), this->m_updateobj, SLOT(run_update()));
    QObject::connect(this->m_update_thread, SIGNAL(finished()), this->m_updateobj, SLOT(deleteLater()));
    QObject::connect(this->m_updateobj, SIGNAL(signal_updateFinished()), this->m_update_thread, SLOT(quit()));
    // GUI<->updater
    QObject::connect(this, SIGNAL(signal_stopGuiUpdater()), this->m_updateobj, SLOT(stopUpdate()), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_computing()), this, SLOT(statusUpdate()), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_pwfound(const QString&)), this, SLOT(infodeskUpdate(const QString&)), Qt::QueuedConnection);
    QObject::connect(this->m_updateobj, SIGNAL(signal_repaint()), this, SLOT(repaint()), Qt::QueuedConnection);

    // run
    this->m_update_thread->start();

    ui->StatusLabel->setText("Date: " + QDate::currentDate().toString("dd.MM.yyyy"));
}


MainWindow::~MainWindow()
{
    // stop and destruct updater
    emit signal_stopGuiUpdater();
    destroyThread(m_update_thread);
    this->m_updateobj = Q_NULLPTR;

    QApplication::restoreOverrideCursor();

    delete ui;
}


void MainWindow::closeEvent(QCloseEvent *event)
{
    // save current attack's data and terminate ongoing attack
    abortAttackActions();

    // call parent's method
    QWidget::closeEvent(event);
}


void MainWindow::openFileButton_clicked()
{
    // choose file
    QString datafileName = QFileDialog::getOpenFileName(this, "Select a file to open...", QDir::homePath());
    if (datafileName == "") {
        ui->StatusLabel->setText("File: no file name specified");
        return;
    }

    ui->StatusLabel->setText("File: " + datafileName);

    // read file
    unsigned int lineCounter = 1;
    QFile inputFile(datafileName);
    if (inputFile.open(QIODevice::ReadOnly))
    {
        // restore system initial state
        m_shadowUsers.clear();
        ui->usersCBox->clear();
        m_initialsetup_usersCBox = 1;

        // populate users' db
        QString shadowFileLine;
        QTextStream in(&inputFile);
        while (!in.atEnd())
        {
            shadowFileLine = in.readLine();

            // collect usernames with their data
            QRegExp rxdelim_userfields("\\:");
            QStringList splittedLine = shadowFileLine.split(rxdelim_userfields);

            QString current_username;
            QString current_algnum;
            QString current_salt;
            QString current_hashofpass;

            try {
                current_username = "";
                current_algnum = "";
                current_salt = "";
                current_hashofpass = "";

                // incorrect data for some user
                if (splittedLine.count() != 9)
                    throw ParsingException{datafileName + "corrupted at line " + lineCounter};

                // user
                current_username = splittedLine.at(0);

                QRegExp rxdelim_passfields("\\$");
                QStringList current_user_data = splittedLine.at(1).split(rxdelim_passfields);

                // incomplete data format (maybe service credentials)
                if (current_user_data.size() != 4)
                    continue;

                // user's data
                current_algnum = current_user_data.at(1);
                current_salt = current_user_data.at(2);
                current_hashofpass = current_user_data.at(3);

                // unsupported hash algorithm
                if (user::getAlgorithmName(current_algnum) == "")
                    throw ParsingException{"user " + current_username + " has unsupported encryption method (scheme id=" + current_algnum + ")"};

                // add user to db
                m_shadowUsers.push_back(user(current_username, current_algnum, current_salt, current_hashofpass));

            } catch (ParsingException &pe)
            {
                ui->GeneralTE->append("Warning: " + QString(pe.what()));
            }

            lineCounter++;
        }
        inputFile.close();
    } else {
        ui->StatusLabel->setText("Cannot open file " + datafileName);
    }

    // show usernames
    ui->retranslateUi(this);
    if (m_shadowUsers.empty())
    {
        ui->StatusLabel->setText("File " + datafileName + ": there is no correct lines");
    }
    else
    {
        QStringList usersList;
        for (int i = 0; i < m_shadowUsers.size(); ++i)
            usersList.append(m_shadowUsers[i].getName());

        QStringListModel *usersModel = new QStringListModel();
        usersModel->setStringList(usersList);
        usersModel->sort(0);

        ui->usersCBox->setModel(usersModel);
        ui->usersCBox->show();

        ui->StatusLabel->setText("File " + datafileName + " parsed");
    }

}


void MainWindow::on_usersCBox_currentTextChanged()
{
    startAttackActions(0);
}


void MainWindow::on_resumeButton_clicked()
{
    startAttackActions(1);
}


void MainWindow::startAttackActions(const bool mode)
{
    // mode 0 - for new calculations
    // mode 1 - for resuming calculations

    QString selected_username;
    if (mode == 0)
    {
        // skip first fire
        if (m_initialsetup_usersCBox == 1)
        {
            m_initialsetup_usersCBox = 0;
            return;
        }

        // get new chosen user
        selected_username = ui->usersCBox->currentText();
    }

    ui->resumeButton->hide();

    if (mode == 0)
    {
        // purge all previous computations' achievements
        clear_cache();
        ui->GeneralTE->clear();
    }

    // prepare GUI
    ui->openFileButton->hide();
    ui->stopButton->show();
    if (mode == 0)
    {
        ui->GeneralTE->clear();
        ui->usersCBox->hide();
        ui->StatusLabel->setText("Performing computations");
    }
    else if (mode == 1)
        ui->StatusLabel->setText("Continuation of computations");

    QApplication::setOverrideCursor(Qt::BusyCursor);

    // get chosen user's data
    if (mode == 0)
    {
        for (int i = 0; i < m_shadowUsers.size(); ++i) {
            if (m_shadowUsers[i].getName() == selected_username)
            {
                m_selecteduserobj = new user(m_shadowUsers.at(i));
                break;
            }
        }
    }
    else if (mode == 1)
    {
        // retrieve data from cache
        QJsonObject loaded_userdata;
        try
        {
            if (!load_cache(loaded_userdata))
                throw ParsingException{"saved data loading exception"};

            // set target's properties
            m_selecteduserobj = new user(loaded_userdata);

            // set attack's properties
            QJsonArray attack_data;
            if (loaded_userdata.contains("Pause") && loaded_userdata["Pause"].isArray())
                attack_data = loaded_userdata["Pause"].toArray();
            else
                throw ParsingException{"saved attack's data parsing exception"};

            for (const QJsonValue& task_propertiesVal: attack_data)
            {
                QJsonObject task_propertiesObj = task_propertiesVal.toObject();

                if (task_propertiesObj.contains("Milestone") && task_propertiesObj["Milestone"].isString() &&
                    task_propertiesObj.contains("Heuristic") && task_propertiesObj["Heuristic"].isDouble() &&
                    task_propertiesObj["Heuristic"].toInt() >= collisionAttackTask_CPU::Heuristic::none &&
                    task_propertiesObj["Heuristic"].toInt() <= collisionAttackTask_CPU::Heuristic::full)
                        collisionAttackTask_CPU::addCacheInit(task_propertiesObj["Milestone"].toString(), static_cast<collisionAttackTask_CPU::Heuristic>(task_propertiesObj["Heuristic"].toInt()));
                else
                    throw ParsingException{"saved attack's tasks' properties parsing exception"};
            }

        } catch (ParsingException &pe)
        {
            // restore app's fresh state
            if (!QString(pe.what()).contains("field not found in saved data"))
                 m_selecteduserobj->deleteLater();
            m_selecteduserobj = Q_NULLPTR;
            ui->GeneralTE->append("Error: " + QString(pe.what()) + ". Invalid cache");
            clear_cache();
            ui->openFileButton->show();
            ui->stopButton->hide();
            QApplication::restoreOverrideCursor();
            return;
        }
    }

    // display target's data
    ui->GeneralTE->append("User: " + m_selecteduserobj->getName());
    ui->GeneralTE->append("Hash scheme: " + user::getAlgorithmName(m_selecteduserobj->getAlgid()));
    ui->GeneralTE->append("Salt: " + m_selecteduserobj->getSalt());
    ui->GeneralTE->append("Hash:");
    ui->GeneralTE->append(m_selecteduserobj->getHash());
    ui->GeneralTE->append("Possible passwords:");
    repaint();

    // prepare to run user's attack in a separete thread
    m_user_thread = new QThread(this);
    m_selecteduserobj->moveToThread(m_user_thread);
    // user thread <-> user obj
    if (mode == 0)
    {
        QObject::connect(m_user_thread, SIGNAL(started()), m_selecteduserobj, SLOT(collision_attack()));
    }
    else if (mode == 1)
    {
        QObject::connect(m_user_thread, SIGNAL(started()), m_selecteduserobj, SLOT(resumed_collision_attack()));
    }

    QObject::connect(m_user_thread, SIGNAL(finished()), m_selecteduserobj, SLOT(deleteLater()));
    QObject::connect(m_selecteduserobj, SIGNAL(signal_attackFinished()), m_user_thread, SLOT(quit()));

    // run hash collisions finding
    m_computation_timer.start();
    m_user_thread->start();
}


void MainWindow::on_stopButton_clicked()
{
    stopAttackActions();
}


void MainWindow::stopAttackActions()
{
    if (m_selecteduserobj == Q_NULLPTR)
        return;

    // stop and destruct target's calculations
    m_selecteduserobj->attack_interrupt();
    destroyThread(m_user_thread);
    m_selecteduserobj = Q_NULLPTR;

    // show results
    ui->StatusLabel->setText("Found " + QString::number(collisionAttackTask_CPU::getHitsNum()) + " collisions in " + QString::number(m_computation_timer.elapsed()/1000) + " sec");
    m_computation_timer.invalidate();

    clear_cache();

    // restore GUI initial state
    if (ui->usersCBox->count())
        ui->usersCBox->show();
    ui->openFileButton->show();
    ui->stopButton->hide();
    QApplication::restoreOverrideCursor();
}


void MainWindow::abortAttackActions()
{
    if (m_selecteduserobj == Q_NULLPTR)
        return;

    // get target's properties
    QJsonObject user_data;

    m_selecteduserobj->write_to_json(user_data);

    // save, stop and destruct target's calculations
    m_selecteduserobj->attack_save();
    destroyThread(m_user_thread);
    m_selecteduserobj = Q_NULLPTR;

    m_computation_timer.invalidate();

    // get attack's properties
    QJsonArray attack_data;
    while (true)
    {
        QPair<QString, collisionAttackTask_CPU::Heuristic> task_savings = collisionAttackTask_CPU::getMilestone();
        if (task_savings.first == QString(""))
            break;

        QJsonObject current_savings;
        current_savings["Milestone"] = task_savings.first;
        current_savings["Heuristic"] = task_savings.second;
        attack_data.push_back(current_savings);
    }

    user_data["Pause"] = attack_data;

    // write data to cachefile
    QJsonDocument docUserAttack;
    docUserAttack.setObject(user_data);

    save_cache(docUserAttack);
}


void MainWindow::infodeskUpdate(const QString& new_password)
{
    // check that it is a brand new finding
    QStringList all_TE_lines = ui->GeneralTE->toPlainText().split(QRegExp("[\n]"),QString::SkipEmptyParts);
    int TE_last_element = all_TE_lines.size() - 1;
    for (int line_index = TE_last_element; line_index >= 0; line_index--)
    {
        if (all_TE_lines.at(line_index) == new_password)
        {
            return;
        }
        else if (all_TE_lines.at(line_index) == QString("Possible passwords:"))
        {
            break;
        }
    }

    ui->GeneralTE->append(new_password);
    repaint();
}


void MainWindow::statusUpdate()
{
    QMutexLocker status_locker(&m_status_mutex);

    QString current_status = ui->StatusLabel->text();
    QString result_status = QString("");
    QString busychar = QString(".");
    uint busychar_counter = 0;

    // count
    for (QString::const_iterator itr = current_status.end() - 1; itr != current_status.begin(); itr--)
    {
        if (*itr == busychar)
            busychar_counter++;
        else
            break;
    }

    // spinning
    if (busychar_counter >= 3)
        result_status = current_status.left(current_status.length() - busychar_counter);
    else
        result_status = current_status + busychar;

    ui->StatusLabel->setText(result_status);
    repaint();
}


void MainWindow::destroyThread(QThread* del_thread)
{
    if (del_thread == Q_NULLPTR)
        return;

    del_thread->quit();
    if (!del_thread->wait(5000))
    {
        del_thread->terminate();
        del_thread->wait();
    }
    delete del_thread;
    del_thread = Q_NULLPTR;
}


bool MainWindow::isCacheExists()
{
    QFileInfo check_file(m_cache_file);

    return check_file.exists() && check_file.isFile();
}


bool MainWindow::load_cache(QJsonObject& json)
{

    QFile loadFile(m_cache_file);

    if (!loadFile.open(QIODevice::ReadOnly))
        return false;

    QByteArray loadData = loadFile.readAll();

    QJsonDocument loadDoc(QJsonDocument::fromJson(loadData));

    if (loadDoc.isNull())
        return false;

    json = loadDoc.object();

    if (json.isEmpty())
        return false;

    return true;
}


bool MainWindow::save_cache(QJsonDocument current_attack_data)
{
    if (!clear_cache())
        return false;

    QDir save_dir;
    if(!save_dir.exists(m_cache_path))
        save_dir.mkpath(m_cache_path);

    QFile jsonCacheFile(m_cache_file);
    if (jsonCacheFile.open(QFile::WriteOnly))
        if (jsonCacheFile.write(current_attack_data.toJson()))
            return true;
    return false;
}


bool MainWindow::clear_cache()
{
    QFile main_cache(m_cache_file);
    if (!main_cache.exists())
        return true;
    if (main_cache.remove())
        return true;
    return false;
}
