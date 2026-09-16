<?php

namespace Tests\Unit\Api\V1;

use App\Http\Controllers\Api\V1\Concerns\LogsApiErrors;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;
use PDOException;
use RuntimeException;
use Tests\TestCase;
use Throwable;

/**
 * Le journal ne doit jamais porter une valeur de requête.
 *
 * Laravel construit le message d'une QueryException en substituant les
 * bindings dans le SQL. Journaliser ce message sur un INSERT de v_gateways
 * écrit le mot de passe du fournisseur SIP en clair dans les logs — reproduit
 * sur une violation d'unicité réelle pendant la revue du lot L2a.
 */
class LogsApiErrorsTest extends TestCase
{
    private const MOT_DE_PASSE = 'S3cr3t-SIP-provider';

    private function journaliseur(): object
    {
        return new class {
            use LogsApiErrors;

            public function journalise(string $contexte, Throwable $e): void
            {
                $this->logApiError($contexte, $e);
            }
        };
    }

    private function erreurBase(): QueryException
    {
        return new QueryException(
            'pgsql',
            'insert into "v_gateways" ("gateway", "username", "password") values (?, ?, ?)',
            ['client_250', '250', self::MOT_DE_PASSE],
            new PDOException('SQLSTATE[23505]: Unique violation')
        );
    }

    private function captureUneLigne(callable $action): string
    {
        $lignes = [];
        Log::listen(function ($message) use (&$lignes) {
            $lignes[] = $message->message;
        });
        $action();

        return implode("\n", $lignes);
    }

    /**
     * Le défaut lui-même : sans ce garde, le message brut suffit à fuiter.
     * Si cette assertion tombe un jour, c'est que Laravel a changé sa
     * construction de message — et le garde devient inutile, pas faux.
     */
    public function test_le_message_brut_dune_erreur_base_contient_bien_la_valeur(): void
    {
        $this->assertStringContainsString(
            self::MOT_DE_PASSE,
            $this->erreurBase()->getMessage(),
            'Laravel substitue les bindings dans le message : ce test documente la cause.'
        );
    }

    public function test_une_erreur_base_ne_journalise_aucune_valeur(): void
    {
        $ligne = $this->captureUneLigne(function () {
            $this->journaliseur()->journalise('API Gateway store error', $this->erreurBase());
        });

        $this->assertStringNotContainsString(self::MOT_DE_PASSE, $ligne);
        $this->assertStringNotContainsString('client_250', $ligne);
        $this->assertStringNotContainsString('250', $ligne);
    }

    public function test_le_sql_reste_diagnosticable_avec_ses_points_dinterrogation(): void
    {
        $ligne = $this->captureUneLigne(function () {
            $this->journaliseur()->journalise('API Gateway store error', $this->erreurBase());
        });

        $this->assertStringContainsString('insert into "v_gateways"', $ligne);
        $this->assertStringContainsString('values (?, ?, ?)', $ligne);
        $this->assertStringContainsString(QueryException::class, $ligne);
        $this->assertStringContainsString('API Gateway store error', $ligne);
    }

    public function test_une_erreur_ordinaire_garde_son_message(): void
    {
        $ligne = $this->captureUneLigne(function () {
            $this->journaliseur()->journalise(
                'API Dialplan store error',
                new RuntimeException('le moteur telephonique est injoignable')
            );
        });

        $this->assertStringContainsString('le moteur telephonique est injoignable', $ligne);
        $this->assertStringContainsString(RuntimeException::class, $ligne);
    }

    /**
     * Contrôleurs AMONT (nemerald-voip/fspbx) qui portent le même motif fuyant.
     *
     * Ils ne sont PAS corrigés ici : les modifier casserait la rebasabilité du
     * fork, et c'est une classe de défaut préexistante qui dépasse ce lot. La
     * liste est figée à dessein — elle ne doit que RÉTRÉCIR. Un contrôleur neuf
     * qui s'y ajouterait ferait échouer le test.
     */
    private const AMONT_CONNUS_A_CORRIGER = [
        'ActiveCallController.php',
        'DeviceController.php',
        'DomainController.php',
        'ExtensionController.php',
        'PhoneNumberController.php',
        'RegistrationController.php',
        'RingGroupController.php',
        'VoicemailController.php',
    ];

    /**
     * Garde structurel : aucun contrôleur de CE lot ne revient au motif fuyant.
     * Le motif vient de l'amont, il reviendra si rien ne le retient.
     */
    public function test_aucun_controleur_neuf_ne_journalise_un_message_dexception(): void
    {
        $fautifs = [];
        foreach (glob(app_path('Http/Controllers/Api/V1/*Controller.php')) as $fichier) {
            $nom = basename($fichier);
            if (in_array($nom, self::AMONT_CONNUS_A_CORRIGER, true)) {
                continue;
            }
            $source = file_get_contents($fichier);
            if (str_contains($source, 'getMessage()') && str_contains($source, 'logger(')) {
                $fautifs[] = $nom;
            }
        }

        $this->assertSame(
            [],
            $fautifs,
            'Ces contrôleurs journalisent un message d\'exception : utiliser logApiError().'
        );
    }

    /**
     * La liste d'exemptions ne doit pas pourrir : un fichier amont disparu ou
     * corrigé doit sortir de la liste, sinon elle finit par tout autoriser.
     */
    public function test_la_liste_damont_exempte_ne_contient_que_des_fautifs_reels(): void
    {
        $obsoletes = [];
        foreach (self::AMONT_CONNUS_A_CORRIGER as $nom) {
            $chemin = app_path('Http/Controllers/Api/V1/' . $nom);
            if (! file_exists($chemin)) {
                $obsoletes[] = $nom . ' (fichier absent)';

                continue;
            }
            $source = file_get_contents($chemin);
            if (! (str_contains($source, 'getMessage()') && str_contains($source, 'logger('))) {
                $obsoletes[] = $nom . ' (corrigé, à retirer de la liste)';
            }
        }

        $this->assertSame([], $obsoletes, 'Exemptions périmées : retirer ces entrées.');
    }
}
