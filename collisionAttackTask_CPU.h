#ifndef COLLISIONATTACKTASK_CPU_H
#define COLLISIONATTACKTASK_CPU_H

#include <QThreadPool>
#include <QThread>
#include <QString>
#include <QDebug>
#include <QPair>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QVector>
#include <QAtomicInt>
#include "crypt.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QVariant>
#include <QPair>
#include <QDir>
#include <parsingexception.h>


class user;


/**
 * @class collisionAttackTask_CPU
 * @brief Performer of the attack based on a password length and a heuristic type.
 * with using of a CPU's computational resourses. Attack's manager.
 */
class collisionAttackTask_CPU : public QRunnable
{
public:

    /**
    * @brief Types of a heuristics.
    *
    * @value none    - brute-force attack with unlimited password length and full alphabet.
    * @value partial - limited password length + limited alphabet.
    * @value full    - username attack + dictionary attack with "rockyou.txt"-type datafiles.
    */
    enum Heuristic
    {
        none,
        partial,
        full
    };

    /**
    * @brief Constructor of specific attack's task.
    * @param heur - Heuristic.
    * @param password_length - size (quantity of characters) of lexical combinations which this task checks for hash collisions.
    * This parameter not used at full Heuristic attack's type.
    * @param milestone - initial letters combo for attack's task. Primary usage - restore suspended ("paused") attack.
    * When reached \a milestone is not set attack's task begins from alphabetically very first value with \a password_length size.
    * @see Heuristic
    */
    collisionAttackTask_CPU(const Heuristic& heur=none, const uint& password_length=0, const QString& milestone="");

    /**
    * @brief Performs the attack based on a heuristic and a password's length. Interrupts by stopAttack().
    * @see brute_force(), stopAttack()
    */
    void run();

    /**
    * @brief Gets an alphabet based on a thread's heuristic type.
    * @param heur - heuristic
    * @value Heuristics::none - retrieve full alphabet
    * @value Heuristics::partial - retrieve limited alphabet.
    * @return Pointer to thread's alphabet.
    * @see m_alphabet, m_part_alphabet
    */
    static const QVector<QString>* getAlphabet(const Heuristic& heur=none);

    /**
    * @brief Gets current target.
    * @return Target's descriptor.
    */
    static const user* getUser(){return m_target;}

    /**
    * @brief Retrieves the oldest saved task's letters combo (savepoint) for current target.
    * Taken item is removed from the reached milestones' database (db).
    * @return The oldest saved reached milestone (returns empty string if there is no more saved letters combo).
    * @see addMilestone()
    */
    static QPair<QString, Heuristic> getMilestone();

    /**
    * @brief Inserts new value into loaded letters combos' db.
    * @param
    * @value thread_init - task's initial letters combo (in case of a full heuristics - <filename;row number>).
    * @value heur - task's heuristic.
    * @see getCacheInit()
    */
    static void addCacheInit(const QString& thread_init, const Heuristic& thread_heur);

    /**
    * @brief Retrieves the oldest value from loaded letters combos' db.
    * @return <thread_init - thread's initial letters combo (milestone), heur - task's heuristic>.
    * @see addCacheInit()
    */
    static QPair<QString, Heuristic> getCacheInit();

    /**
    * @brief Retrieves the oldest founded password for current target. Taken item is removed from the found passwords' database.
    * @return The oldest found password (returns empty string if there is no more found passwords).
    * @see addHit(), clearHits()
    */
    static QString getHit();

    /**
    * @brief Gets total quantity of founded passwords for current target.
    * @return Total quantity of found passwords.
    */
    static unsigned int getHitsNum(){return m_hits_num;}

    /**
    * @brief Gets password's "optimal" length limit (used in the partial heuristic mode).
    * @see run(), Heuristic
    */
    static unsigned char getOptimalMaxPL(){return m_optimal_max_pass_length;}

    /**
    * @brief Interrupts thread's computations.
    * @see startAttack(), saveAttack()
    */
    static void stopAttack(){m_attack_is_on.store(0);}

    /**
    * @brief Saves current unevaluated password variant, interrupts thread's computations.
    * @see stopAttack(), startAttack()
    */
    static void saveAttack(){clearCacheInit(); m_attack_is_on.store(2);}

    /**
    * @brief Getter of m_attack_is_on value.
    * @return
    * @value 0 - attack is off.
    * @value 1 - attack is on.
    * @value 2 - attack is off and saved (paused).
    * @see setNewTarget(), stopAttack(), startAttack(), saveAttack()
    */
    static uint attackStatus(){return (uint)m_attack_is_on.loadAcquire();}

    /**
    * @brief (Re)initialization of the attack's target and it's associated computations and findings.
    * @param target - pointer to user class.
    * @see user, stopAttack(), clearHits()
    */
    static void setNewTarget(user* const target);

private:
    static user* m_target;

    int m_password_length;

    /**
    * @brief Task's type of a heuristic.
    */
    Heuristic m_heur;

    /**
    * @brief Initial letters combo for attack's task.
    */
    QString m_milestone;

    /**
    * @brief Attack's status.
    * @see attackStatus(), stopAttack()
    */
    static QAtomicInt m_attack_is_on;

    /**
    * @brief Full alphabet.
    */
    static const QVector<QString> m_alphabet;

    /**
    * @brief Partial alphabet: num + alpha + most frequently-used special characters.
    */
    static const QVector<QString> m_part_alphabet;

    /**
    * @brief Used during partial heuristic attack.
    */
    static const unsigned char m_optimal_max_pass_length;

    /**
    * @brief Buffer (db) with founded passwords.
    * (based on collisions between passwords' hashes and the user's password hash).
    * @see addHit(), clearHits(), getHit()
    */
    static QQueue<QString> m_found_collisions;

    /**
    * @brief Total number of found passwords.
    */
    static unsigned int m_hits_num;

    /**
    * @brief Hits' db guard.
    * @see addHit(), clearHits(), getHit()
    */
    static QMutex m_coll_mutex;

    /**
    * @brief Buffer with the latest unchecked task' letters combo / heuristic for saving to cache (savepoint).
    * @see saveAttack(), addMilestone(), getMilestone(), clearMilestones()
    */
    static QQueue<QPair<QString, Heuristic>> m_milestonesToCache;

    /**
    * @brief Buffer with the latest unchecked task' letters combo / heuristc loaded from cache.
    * @see addCacheInit(), getCacheInit()
    */
    static QQueue<QPair<QString, Heuristic>> m_milestonesFromCache;

    /**
    * @brief Reached milestones' db guard.
    * @see addMilestone(), getMilestone(), addInit(), getInit()
    */
    static QMutex m_milestone_mutex;

    /**
    * @brief Format for crypt(3) func: $id$salt.
    */
    static QString m_algid_salt;

    /**
    * @brief Allows task's computations to start.
    * @see stopAttack(), pauseAttack()
    */
    static void startAttack(){m_attack_is_on.store(1);}

    /**
    * @brief Reads all dictinaries (~/.local/share/dictionaries/\*.txt) line by line and calls evaluate_password() for every password variant.
    * Interruptable with stopAttack() and saveAttack() methods.
    * @return Collision found (true) or didn't found (false).
    * @see run(), stopAttack(), saveAttack(), evaluate_password()
    */
    bool dictionary_attack();

    /**
    * @brief Iterating through all password variations with respect to thread's password length and heuristic.
    * Interruptable with stopAttack() and saveAttack(). Calls evaluate_password() for every constructed password variant.
    * @return Collision found (true) or didn't found (false).
    * @see run(), stopAttack(), saveAttack(), evaluate_password()
    */
    bool brute_force();

    /**
    * @brief Gets lexicographically first password variant with respect to task's alphabet.
    * In case of a resumed attack very first initial password begins from a given task's milestone
    * (one must set \a use_task_milestone to true).
    * @param use_task_milestone - use task's milestone's data (true) or not (false).
    * @param length - password length.
    * @return first password variant.
    * @see brute_force(), next_password(), getAlphabet()
    */
    QString initial_password(const bool& use_task_milestone, const uint& length);

    /**
    * @brief Gets the next (in a lexicographical sense) password variant with respect to current password variant
    * and getAlphabet().
    * This method is using by brute_force() in order to decrease memory consumption.
    *
    * @param
    * @value [in] current_pass - current password variant (letters' combo).
    * @value [out] next_pass - next (based on current) password variant.
    *
    * @return
    * @value 3 - current_pass contains characters that are not in the alphabet for that thread.
    * @value 2 - length of the current_pass does not match thread's password length setting.
    * @value 1 - there is no next password variant (current password is lexicographically a last one).
    * @value 0 - next password variant successfully found and stored in next_pass.
    *
    * @see brute_force(), getAlphabet()
    */
    unsigned char next_password(const QString& current_pass, QString& next_pass);

    /**
    * @brief Calls crypt(3) to create hash from password variant and user's salt. Calls compare_hashes(),
    * emits addHit() signal if a collision found.
    * @param password - password variant for verification.
    * @return
    * @value true  - collision found.
    * @value false - collision didn't found.
    * @see brute_force(), compare_hashes(), crypt(3), addHit()
    */
    bool evaluate_password(const QString& password);

    /**
    * @brief Determines hit it or not.
    * @param current_hash - hash of a password variant for verification.
    * @return
    * @value true  - hash broken.
    * @value false - hash isn't broken.
    * @see brute_force(), evaluate_password()
    */
    bool compare_hashes(const QString& current_hash);

    /**
    * @brief Inserts new value to founded passwords' db. Called when evaluate_password() finds a matching password.
    * @param new_finding - founded collision result (matching password).
    * @see evaluate_password()
    */
    void addHit(const QString& new_finding);

    /**
    * @brief Cleans the founded passwords' db - m_found_collisions.
    * @see setNewTarget()
    */
    static void clearHits();

    /**
    * @brief Inserts new value to saved letters combos' (savepoints) db.
    * @param
    * @value thread_milestone - thread's last unchecked letters combo
    * @value heur - thread's heuristic
    * @see saveAttack(), getMilestone()
    */
    void addMilestone(const QString& thread_milestone, const Heuristic& thread_heur);

    /**
    * @brief Cleans saved letters combo variants (savepoints).
    * @see addMilestone()
    */
    static void clearMilestones();

    /**
    * @brief Cleans loaded letters combos' db.
    * @see addCacheInit, getCacheInit()
    */
    static void clearCacheInit();
};


#endif // COLLISIONATTACKTASK_CPU_H
