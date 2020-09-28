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


class user;


/**
 * @class collisionAttackTask_CPU
 * @brief Performer of the attack based on a password length and a heuristics type
 * with using of a CPU's computational resourses.
 */
class collisionAttackTask_CPU : public QRunnable
{
public:

    /**
    * @brief Types of a heuristics.
    *
    * @value none    - brute-force attack with unlimited password length and full alphabet.
    * @value partial - limited password length + limited alphabet.
    * @value full    - username attack + dictionary attack with rockyou.txt (not implemented yet).
    */
    enum Heuristics
    {
        none,
        partial,
        full
    };

    collisionAttackTask_CPU(const Heuristics& heur=none, const unsigned int password_length = 0);

    /**
    * @brief Performs the attack based on a heuristics and a password's length. Interrupts by stopAttack().
    * @see brute_force(), stopAttack()
    */
    void run();

    /**
    * @brief Gets an alphabet based on a thread's heuristics type.
    * @param heur - heuristics
    * @value Heuristics::none - full alphabet
    * @value Heuristics::partial - limited alphabet.
    * @return Pointer to thread's alphabet.
    * @see m_alphabet, m_part_alphabet
    */
    static const QVector<QString>* getAlphabet(const Heuristics& heur=none);

    /**
    * @brief Gets current target.
    * @return Target's descriptor.
    */
    static const user* getUser(){return m_target;}

    /**
    * @brief Retrieves the oldest founded password for current target. Taken item is removed from the found passwords' database (db).
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
    * @brief Gets password's "optimal" length limit (used in the partial heuristics mode).
    * @see run(), Heuristics
    */
    static unsigned char getOptimalMaxPL(){return m_optimal_max_pass_length;}

    /**
    * @brief Interrupts thread's computations.
    * @see Heuristics
    */
    static void stopAttack(){m_attack_is_on.store(0);}

    /**
    * @brief Getter of m_attack_is_on value.
    * @return
    * @value 1 - attack is on.
    * @value 0 - attack is off.
    * @see setNewTarget(), stopAttack()
    */
    static bool attackStatus(){return (bool)m_attack_is_on.loadAcquire();}

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
    * @brief Current thread's type of a heuristics.
    * @see Heuristics
    */
    Heuristics m_heur;

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
    * @brief Used during partial heuristics attack.
    */
    static const unsigned char m_optimal_max_pass_length;

    /**
    * @brief Buffer (db) with founded passwords.
    * (based on collisions between passwords' hashes and the user's password hash).
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
    * @brief Format for crypt(3) func: $id$salt.
    */
    static QString m_algid_salt;

    /**
    * @brief Determines hit it or not.
    * @param current_hash - hash of a password variant for verification.
    * @return
    * @value TRUE  - hash broken.
    * @value FALSE - hash isn't broken.
    * @see brute_force(), evaluate_password()
    */
    bool compare_hashes(const QString& current_hash);

    /**
    * @brief Calls crypt(3) to create hash from password variant and user's salt. Calls compare_hashes(),
    * emits addHit() signal if a collision found.
    * @param password - password variant for verification.
    * @return
    * @value TRUE  - collision found.
    * @value FALSE - collision didn't found.
    * @see brute_force(), compare_hashes(), crypt(3), addHit()
    */
    bool evaluate_password(const QString& password);

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
    * @brief Iterating through all password variations with respect to thread's password length and heuristic.
    * Interruptable with stopAttack(). Calls evaluate_password() for every constructed password variant.
    * @return Collision found (1) or didn't found (0).
    * @see stopAttack(), evaluate_password()
    */
    bool brute_force();

    /**
    * @brief Gets lexicographically first password variant with respect to thread's alphabet.
    *
    * @param length - password length.
    * @return first password variant.
    * @see brute_force(), next_password(), getAlphabet()
    */
    QString initial_password(const uint& length);

    /**
    * @brief Gets the next (in a lexicographical sense) password variant with respect to current password variant
    * and getAlphabet().
    * This method is using by brute_force() in order to decrease memory consumption.
    *
    * @param
    * @value [in] current_pass - current password variant.
    * @value [inout] next_pass - next (based on current) password variant.
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
};


#endif // COLLISIONATTACKTASK_CPU_H
