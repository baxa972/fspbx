<?php

namespace App\Http\Controllers\Api\V1\Concerns;

use Illuminate\Database\QueryException;
use Throwable;

/**
 * Journalisation d'erreur qui ne recopie jamais une valeur de requête.
 *
 * Laravel construit le message d'une QueryException avec
 * Str::replaceArray('?', $bindings, $sql) : les BINDINGS SONT SUBSTITUÉS DANS
 * LE SQL. Journaliser $e->getMessage() sur un INSERT de v_gateways écrit donc
 * le mot de passe du fournisseur SIP en clair dans storage/logs/laravel.log —
 * reproduit sur une violation d'unicité réelle.
 *
 * Ce journaliseur garde tout ce qui sert au diagnostic (classe, fichier,
 * ligne, et pour une erreur base le SQL avec ses points d'interrogation
 * intacts) et laisse les valeurs dehors.
 */
trait LogsApiErrors
{
    protected function logApiError(string $contexte, Throwable $e): void
    {
        $lieu = $e->getFile() . ':' . $e->getLine();

        if ($e instanceof QueryException) {
            // getSql() rend la requête AVANT substitution : les valeurs restent
            // des « ? ». getBindings() n'est jamais lu, volontairement.
            logger(sprintf(
                '%s: %s [%s] sql=%s at %s',
                $contexte,
                $e->getCode() ?: 'db',
                get_class($e),
                $e->getSql(),
                $lieu
            ));

            return;
        }

        logger(sprintf('%s: %s [%s] at %s', $contexte, $e->getMessage(), get_class($e), $lieu));
    }
}
